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

export async function verify(
  token: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const chain: ChainLink[] = [];
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 60;

  // If DPoP proof is provided, verify it against the outermost token
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

  // Walk the chain
  let current = token;
  let depth = 0;
  let childExp: number | undefined;
  let childIat: number | undefined;
  let rootSub: string | undefined;
  let rootAud: string | undefined;

  while (current) {
    const header = decodeProtectedHeader(current);
    const isFrenchToast = header.typ === FT_TYPE;
    const payload = decodeJwt(current);
    const issuer = payload.iss;

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

    // Verify signature (jose validates exp and iat by default for depth 0)
    // For parent tokens we pass clockTolerance to handle reasonable skew
    try {
      await jwtVerify(current, getKey as Parameters<typeof jwtVerify>[1], {
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

    // exp MUST be present
    if (exp === undefined) {
      throw new ChainVerificationError('Token is missing "exp" claim', depth);
    }

    // iat MUST be present
    if (iat === undefined) {
      throw new ChainVerificationError('Token is missing "iat" claim', depth);
    }

    // iat MUST be before exp
    if (iat > exp) {
      throw new ChainVerificationError(
        '"iat" must not be after "exp"',
        depth,
      );
    }

    // iat MUST NOT be in the future (with clock tolerance)
    if (iat > now + clockTolerance) {
      throw new ChainVerificationError(
        '"iat" is in the future',
        depth,
      );
    }

    // exp MUST NOT be in the past (with clock tolerance)
    if (exp < now - clockTolerance) {
      throw new ChainVerificationError(
        'Token is expired',
        depth,
      );
    }

    // ── Chain constraints ──

    if (depth > 0) {
      // Child exp MUST NOT exceed parent exp
      if (childExp !== undefined && childExp > exp) {
        throw new ExpiryExceededError();
      }

      // Child iat MUST NOT be before parent iat (child was issued after parent)
      if (childIat !== undefined && childIat < iat) {
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

    if (depth === 0) {
      rootSub = payload.sub as string | undefined;
      rootAud = payload.aud as string | undefined;
    }
    childExp = exp;
    childIat = iat;

    chain.push({
      header: header as unknown as Record<string, unknown>,
      payload: payload as unknown as Record<string, unknown>,
      depth,
    });

    // Follow ft_parent in header
    if (isFrenchToast && header[FT_PARENT_HEADER]) {
      current = header[FT_PARENT_HEADER] as string;
      depth++;
    } else {
      break;
    }
  }

  return { valid: true, chain };
}
