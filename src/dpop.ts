import {
  SignJWT,
  jwtVerify,
  exportJWK,
  calculateJwkThumbprint,
  EmbeddedJWK,
} from 'jose';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import type { DPoPOptions } from './types.js';
import { DPoPVerificationError } from './errors.js';

/**
 * Create a DPoP proof JWT per RFC 9449.
 */
export async function createDPoPProof(options: DPoPOptions): Promise<string> {
  const alg = options.algorithm ?? 'ES256';
  const publicJwk = await exportJWK(options.publicKey);

  // ath = base64url(sha256(access_token))
  const ath = createHash('sha256')
    .update(options.accessToken, 'ascii')
    .digest('base64url');

  return new SignJWT({
    jti: randomUUID(),
    htm: options.method,
    htu: options.url,
    ath,
  })
    .setProtectedHeader({
      alg,
      typ: 'dpop+jwt',
      jwk: publicJwk,
    })
    .setIssuedAt()
    .sign(options.privateKey);
}

/**
 * Verify a DPoP proof against an access token's cnf.jkt claim.
 */
export async function verifyDPoPProof(
  dpopProof: string,
  accessToken: string,
  expectedJkt: string,
  method: string,
  url: string,
): Promise<void> {
  // Verify the DPoP proof signature using the embedded JWK
  const { payload, protectedHeader } = await jwtVerify(dpopProof, EmbeddedJWK, {
    typ: 'dpop+jwt',
  }).catch((err) => {
    throw new DPoPVerificationError(`Invalid DPoP proof signature: ${err.message}`);
  });

  // Check typ
  if (protectedHeader.typ !== 'dpop+jwt') {
    throw new DPoPVerificationError('DPoP proof typ must be dpop+jwt');
  }

  // Check the JWK thumbprint matches cnf.jkt
  const jwk = protectedHeader.jwk;
  if (!jwk) {
    throw new DPoPVerificationError('DPoP proof must contain jwk in header');
  }

  const thumbprint = await calculateJwkThumbprint(jwk, 'sha256');
  if (thumbprint !== expectedJkt) {
    throw new DPoPVerificationError(
      'DPoP proof JWK thumbprint does not match cnf.jkt',
    );
  }

  // Check htm
  if (payload.htm !== method) {
    throw new DPoPVerificationError(
      `DPoP htm mismatch: expected ${method}, got ${payload.htm}`,
    );
  }

  // Check htu
  if (payload.htu !== url) {
    throw new DPoPVerificationError(
      `DPoP htu mismatch: expected ${url}, got ${payload.htu}`,
    );
  }

  // Check ath (access token hash)
  const expectedAth = createHash('sha256')
    .update(accessToken, 'ascii')
    .digest('base64url');
  if (payload.ath !== expectedAth) {
    throw new DPoPVerificationError('DPoP ath does not match access token hash');
  }
}
