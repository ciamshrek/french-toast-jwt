import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, calculateJwkThumbprint } from 'jose';
import { FT_TYPE, FT_PARENT_HEADER } from './types.js';
import type { FrenchToastOptions } from './types.js';
import { ExpiryExceededError, SubjectMismatchError } from './errors.js';

export async function frenchToast(
  parentToken: string,
  options: FrenchToastOptions,
): Promise<string> {
  const parentPayload = decodeJwt(parentToken);

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

  // Validate exp doesn't exceed parent
  if (exp && parentExp && exp > parentExp) {
    throw new ExpiryExceededError();
  }

  const alg = options.algorithm ?? 'ES256';

  // Build the JWT
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
    .setProtectedHeader({
      alg,
      typ: FT_TYPE,
      [FT_PARENT_HEADER]: parentToken,
    })
    .setIssuer(options.issuer)
    .setAudience(options.audience)
    .setIssuedAt();

  if (exp) {
    builder.setExpirationTime(exp);
  }

  return builder.sign(options.privateKey);
}
