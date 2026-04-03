import { generateKeyPair, SignJWT, exportJWK, calculateJwkThumbprint } from 'jose';

/**
 * Generate an ES256 key pair and return both keys + JWK thumbprint.
 */
export async function makeKeyPair() {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
  return { publicKey, privateKey, publicJwk, thumbprint };
}

/**
 * Create a fake "Authorization Server" token (simulates what Auth0/etc would issue).
 */
export async function makeRootToken(options: {
  privateKey: CryptoKey | Uint8Array;
  issuer: string;
  subject: string;
  audience: string;
  extraClaims?: Record<string, unknown>;
  expiresIn?: number;
  nextHopThumbprint?: string;
}) {
  const builder = new SignJWT({
    ...options.extraClaims,
    ...(options.nextHopThumbprint
      ? { cnf: { jkt: options.nextHopThumbprint } }
      : {}),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
    .setIssuer(options.issuer)
    .setSubject(options.subject)
    .setAudience(options.audience)
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ? `${options.expiresIn}s` : '1h');

  return builder.sign(options.privateKey);
}
