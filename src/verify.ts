import {
  jwtVerify,
  decodeJwt,
  decodeProtectedHeader,
  createRemoteJWKSet,
} from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { FT_TYPE, FT_PARENT_HEADER } from './types.js';
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

export async function verify(
  token: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 60;
  const maxDepth = options.maxDepth ?? MAX_CHAIN_DEPTH;

  // ── Phase 1: Collect the chain (decode only, no verification) ──
  // Walk ft_parent from outermost to root, collecting raw tokens.

  const rawTokens: string[] = [];
  let current = token;

  while (current) {
    if (rawTokens.length > maxDepth) {
      throw new ChainVerificationError(
        `Chain depth exceeds maximum of ${maxDepth}`,
        rawTokens.length,
      );
    }

    rawTokens.push(current);

    const header = decodeProtectedHeader(current);
    if (header.typ === FT_TYPE && header[FT_PARENT_HEADER]) {
      current = header[FT_PARENT_HEADER] as string;
    } else {
      break;
    }
  }

  // ── Phase 2: Verify inside-out (root first) ──
  // If the root is invalid, nothing derived from it matters.

  const chain: ChainLink[] = [];
  let parentExp: number | undefined;
  let parentIat: number | undefined;
  let rootSub: string | undefined;
  let rootAud: string | undefined;

  // Iterate from root (last collected) to outermost (first collected)
  for (let i = rawTokens.length - 1; i >= 0; i--) {
    const raw = rawTokens[i];
    const header = decodeProtectedHeader(raw);
    const payload = decodeJwt(raw);
    const issuer = payload.iss;
    const depth = rawTokens.length - 1 - i; // root = 0 in verification order

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
      // This is the root token — establish the baseline
      rootSub = payload.sub as string | undefined;
      rootAud = payload.aud as string | undefined;
    } else {
      // Child exp MUST NOT exceed parent exp
      if (parentExp !== undefined && exp > parentExp) {
        throw new ExpiryExceededError();
      }

      // Child iat MUST NOT be before parent iat
      if (parentIat !== undefined && iat < parentIat) {
        throw new ChainVerificationError(
          'Child "iat" is before parent "iat"',
          depth,
        );
      }

      // Sub MUST match throughout the chain
      if (rootSub && payload.sub !== rootSub) {
        throw new SubjectMismatchError();
      }

      // Aud MUST match throughout the chain
      if (rootAud && payload.aud !== rootAud) {
        throw new AudienceMismatchError();
      }
    }

    parentExp = exp;
    parentIat = iat;

    chain.push({
      header: header as unknown as Record<string, unknown>,
      payload: payload as unknown as Record<string, unknown>,
      depth: i, // depth in the output: 0 = outermost, N = root
    });
  }

  // ── Phase 3: DPoP verification (after outermost signature is verified) ──

  if (options.dpopProof) {
    if (!options.method || !options.url) {
      throw new Error('method and url are required when dpopProof is provided');
    }

    const outerPayload = decodeJwt(token);
    const cnf = outerPayload.cnf as { jkt?: string } | undefined;
    if (cnf?.jkt) {
      await verifyDPoPProof(
        options.dpopProof,
        token,
        cnf.jkt,
        options.method,
        options.url,
      );
    }
  }

  // Reverse so output is outer-to-root (depth 0 = outermost)
  chain.reverse();

  return { valid: true, chain };
}
