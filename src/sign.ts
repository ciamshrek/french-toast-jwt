import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, calculateJwkThumbprint } from 'jose';
import { createHash } from 'node:crypto';
import { FT_TYPE, FT_PARENT_HEADER, FT_ISS_HEADER, FT_DEP_HEADER } from './types.js';
import type { FrenchToastOptions } from './types.js';
import { ExpiryExceededError, SubjectMismatchError, FrenchToastError } from './errors.js';

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'ascii').digest('base64url');
}

export async function frenchToast(
  parentToken: string,
  options: FrenchToastOptions,
): Promise<string> {
  const parentPayload = decodeJwt(parentToken);
  const parentHeader = decodeProtectedHeader(parentToken);

  // Validate sub matches
  if (options.extraClaims?.sub && options.extraClaims.sub !== parentPayload.sub) {
    throw new SubjectMismatchError();
  }

  // Compute exp: either caller's expiresIn or inherit parent's, capped to parent's
  const now = Math.floor(Date.now() / 1000);
  const parentExp = parentPayload.exp as number | undefined;
  let exp: number | undefined;
  if (options.expiresIn) {
    exp = now + options.expiresIn;
    if (parentExp && exp > parentExp) {
      exp = parentExp;
    }
  } else {
    exp = parentExp;
  }

  if (exp && parentExp && exp > parentExp) {
    throw new ExpiryExceededError();
  }

  // ── ft_dep: monotonically decreasing depth ──
  const parentDep = parentHeader[FT_DEP_HEADER] as number | undefined;

  if (parentDep !== undefined && parentDep <= 0) {
    throw new FrenchToastError('Parent token does not allow further delegation (ft_dep is 0)');
  }

  let ftDep: number | undefined;
  if (options.maxDepth !== undefined) {
    // Caller wants to set ft_dep — must be <= parent's ft_dep - 1
    if (parentDep !== undefined && options.maxDepth > parentDep - 1) {
      ftDep = parentDep - 1;
    } else {
      ftDep = options.maxDepth;
    }
  } else if (parentDep !== undefined) {
    // Inherit and decrement
    ftDep = parentDep - 1;
  }
  // If neither parent nor caller set it, leave it undefined (unbound)

  // ── ft_iss: monotonically shrinking allowed issuers ──
  const parentIss = parentHeader[FT_ISS_HEADER] as string[] | undefined;

  let ftIss: string[] | undefined;
  if (options.allowedIssuers !== undefined) {
    if (parentIss !== undefined) {
      // Must be a subset of parent's ft_iss
      const parentSet = new Set(parentIss);
      ftIss = options.allowedIssuers.filter(iss => parentSet.has(iss));
    } else {
      ftIss = options.allowedIssuers;
    }
  } else if (parentIss !== undefined) {
    // Inherit from parent
    ftIss = parentIss;
  }
  // If neither parent nor caller set it, leave it undefined (all issuers accepted)

  const alg = options.algorithm ?? 'ES256';

  // Build the protected header
  const protectedHeader: Record<string, unknown> = {
    alg,
    typ: FT_TYPE,
    [FT_PARENT_HEADER]: hashToken(parentToken),
  };

  if (ftIss !== undefined) {
    protectedHeader[FT_ISS_HEADER] = ftIss;
  }

  if (ftDep !== undefined) {
    protectedHeader[FT_DEP_HEADER] = ftDep;
  }

  const builder = new SignJWT({
    sub: parentPayload.sub,
    ...options.extraClaims,
    ...(options.nextHopPublicKey
      ? {
          cnf: {
            jkt: await calculateJwkThumbprint(
              await exportJWK(options.nextHopPublicKey),
              'sha256',
            ),
          },
        }
      : {}),
  })
    .setProtectedHeader(protectedHeader as any)
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt();

  if (exp) {
    builder.setExpirationTime(exp);
  }

  return builder.sign(options.privateKey);
}
