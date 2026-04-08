import {
  jwtVerify,
  decodeJwt,
  decodeProtectedHeader,
  createRemoteJWKSet,
} from 'jose';
import { createHash } from 'node:crypto';
import type { JWTVerifyGetKey } from 'jose';
import { FT_TYPE, FT_PARENT_HEADER, FT_ISS_HEADER, FT_DEP_HEADER, CHAIN_DELIMITER } from './types.js';
import type { KeyInput, VerifyOptions, VerifyResult, ChainLink } from './types.js';
import {
  ChainVerificationError,
  SubjectMismatchError,
  AudienceMismatchError,
  ExpiryExceededError,
} from './errors.js';
import { verifyDPoPProof } from './dpop.js';
import { discoverKeys } from './discovery.js';

const MAX_CHAIN_DEPTH = 10;

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'ascii').digest('base64url');
}

/**
 * Verify an FT-JWT chain.
 *
 * @param chain - Either a `&`-delimited chain string (outermost first, root last)
 *                or an array of token strings in the same order.
 * @param options - Verification options.
 */
export async function verify(
  chain: string | string[],
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 60;
  const maxDepth = options.maxDepth ?? MAX_CHAIN_DEPTH;

  // ── Phase 1: Parse the chain ──

  const rawTokens: string[] = typeof chain === 'string'
    ? chain.split(CHAIN_DELIMITER)
    : chain;

  if (rawTokens.length === 0) {
    throw new ChainVerificationError('Chain is empty', 0);
  }

  if (rawTokens.length > maxDepth) {
    throw new ChainVerificationError(
      `Chain depth exceeds maximum of ${maxDepth}`,
      rawTokens.length,
    );
  }

  // ── Phase 2: Check allowed issuers (before any key discovery or network requests) ──

  if (options.allowedIssuers) {
    const allowed = new Set(options.allowedIssuers);
    for (let i = 0; i < rawTokens.length; i++) {
      const payload = decodeJwt(rawTokens[i]);
      const issuer = payload.iss as string | undefined;
      if (!issuer || !allowed.has(issuer)) {
        throw new ChainVerificationError(
          `Issuer "${issuer ?? '(missing)'}" is not in the allowed issuers list`,
          i,
        );
      }
    }
  }

  // ── Phase 3: Verify hash binding ──
  // Each non-root token's ft_parent must equal sha256(next token in array)

  for (let i = 0; i < rawTokens.length - 1; i++) {
    const header = decodeProtectedHeader(rawTokens[i]);
    const expectedHash = hashToken(rawTokens[i + 1]);
    const actualHash = header[FT_PARENT_HEADER] as string | undefined;

    if (!actualHash) {
      throw new ChainVerificationError(
        'Token is missing "ft_parent" header',
        i,
      );
    }

    if (actualHash !== expectedHash) {
      throw new ChainVerificationError(
        'ft_parent hash does not match next token in chain',
        i,
      );
    }
  }

  // ── Phase 4: Verify signatures and claims inside-out (root first) ──

  const result: ChainLink[] = [];
  let parentExp: number | undefined;
  let parentIat: number | undefined;
  let rootSub: string | undefined;
  let rootAud: string | undefined;

  for (let i = rawTokens.length - 1; i >= 0; i--) {
    const raw = rawTokens[i];
    const header = decodeProtectedHeader(raw);
    const payload = decodeJwt(raw);
    const issuer = payload.iss;
    const depth = rawTokens.length - 1 - i;

    // Resolve key for this issuer
    let getKey: JWTVerifyGetKey | KeyInput;
    if (options.resolveKey && issuer) {
      const resolved = await options.resolveKey(issuer);
      if (typeof resolved === 'string') {
        getKey = createRemoteJWKSet(new URL(resolved));
      } else {
        getKey = resolved;
      }
    } else if (issuer) {
      getKey = await discoverKeys(issuer);
    } else {
      throw new ChainVerificationError('Token has no issuer', depth);
    }

    // Verify signature
    try {
      await jwtVerify(raw, getKey as Parameters<typeof jwtVerify>[1], {
        clockTolerance,
      });
    } catch (err) {
      throw new ChainVerificationError(
        `Signature verification failed: ${(err as Error).message}`,
        depth,
      );
    }

    const exp = payload.exp as number | undefined;
    const iat = payload.iat as number | undefined;

    // ── Temporal bounds ──

    if (exp === undefined) {
      throw new ChainVerificationError('Token is missing "exp" claim', depth);
    }

    if (iat === undefined) {
      throw new ChainVerificationError('Token is missing "iat" claim', depth);
    }

    if (iat > exp) {
      throw new ChainVerificationError('"iat" must not be after "exp"', depth);
    }

    if (iat > now + clockTolerance) {
      throw new ChainVerificationError('"iat" is in the future', depth);
    }

    if (exp < now - clockTolerance) {
      throw new ChainVerificationError('Token is expired', depth);
    }

    // ── Chain constraints (for non-root tokens) ──

    if (depth === 0) {
      rootSub = payload.sub as string | undefined;
      rootAud = payload.aud as string | undefined;
    } else {
      if (parentExp !== undefined && exp > parentExp) {
        throw new ExpiryExceededError();
      }

      if (parentIat !== undefined && iat < parentIat) {
        throw new ChainVerificationError(
          'Child "iat" is before parent "iat"',
          depth,
        );
      }

      if (rootSub && payload.sub !== rootSub) {
        throw new SubjectMismatchError();
      }

      if (rootAud && payload.aud !== rootAud) {
        throw new AudienceMismatchError();
      }

      // ── ft_iss: parent's allowed issuers must permit this token's issuer ──
      // Read ft_iss from the parent token (i+1 in the array, which was processed before us)
      const parentHeader = decodeProtectedHeader(rawTokens[i + 1]);
      const parentFtIss = parentHeader[FT_ISS_HEADER] as string[] | undefined;
      if (parentFtIss && issuer && !parentFtIss.includes(issuer)) {
        throw new ChainVerificationError(
          `Issuer "${issuer}" is not allowed by parent's ft_iss`,
          depth,
        );
      }

      // ── ft_dep: parent's depth must allow this delegation ──
      const parentFtDep = parentHeader[FT_DEP_HEADER] as number | undefined;
      if (parentFtDep !== undefined && parentFtDep <= 0) {
        throw new ChainVerificationError(
          'Parent token does not allow further delegation (ft_dep is 0)',
          depth,
        );
      }

      // ── ft_iss/ft_dep monotonic reduction: child must be subset/less ──
      const childFtIss = header[FT_ISS_HEADER] as string[] | undefined;
      if (parentFtIss && childFtIss) {
        const parentSet = new Set(parentFtIss);
        for (const iss of childFtIss) {
          if (!parentSet.has(iss)) {
            throw new ChainVerificationError(
              `Child ft_iss contains "${iss}" which is not in parent's ft_iss`,
              depth,
            );
          }
        }
      }

      const childFtDep = header[FT_DEP_HEADER] as number | undefined;
      if (parentFtDep !== undefined && childFtDep !== undefined && childFtDep >= parentFtDep) {
        throw new ChainVerificationError(
          'Child ft_dep must be less than parent ft_dep',
          depth,
        );
      }
    }

    parentExp = exp;
    parentIat = iat;

    result.push({
      header: header as unknown as Record<string, unknown>,
      payload: payload as unknown as Record<string, unknown>,
      depth: i,
    });
  }

  // ── Phase 5: DPoP verification (after all signatures are verified) ──

  if (options.dpopProof) {
    if (!options.method || !options.url) {
      throw new Error('method and url are required when dpopProof is provided');
    }

    const outermost = rawTokens[0];
    const outerPayload = decodeJwt(outermost);
    const cnf = outerPayload.cnf as { jkt?: string } | undefined;
    if (cnf?.jkt) {
      // ath binds to the full chain string
      const chainString = rawTokens.join(CHAIN_DELIMITER);
      await verifyDPoPProof(
        options.dpopProof,
        chainString,
        cnf.jkt,
        options.method,
        options.url,
      );
    }
  }

  // Reverse so output is outer-to-root (depth 0 = outermost)
  result.reverse();

  return { valid: true, chain: result };
}
