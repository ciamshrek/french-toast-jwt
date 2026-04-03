import { describe, it, expect } from 'vitest';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { frenchToast } from '../src/sign.js';
import { FT_TYPE, FT_PARENT_HEADER } from '../src/types.js';
import { makeKeyPair, makeRootToken } from './helpers.js';

describe('frenchToast (sign)', () => {
  it('should create a french-toast token with ft_parent in header', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const rootToken = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc123',
      audience: 'https://rs.example.com',
      extraClaims: { scope: 'read write delete' },
    });

    const ftToken = await frenchToast(rootToken, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
      extraClaims: { scope: 'read write' },
    });

    const header = decodeProtectedHeader(ftToken);
    const payload = decodeJwt(ftToken);

    expect(header.typ).toBe(FT_TYPE);
    expect(header[FT_PARENT_HEADER]).toBe(rootToken);
    expect(payload.iss).toBe('https://client1.example.com/client_id.json');
    expect(payload.aud).toBe('https://rs.example.com');
    expect(payload.sub).toBe('user|abc123');
    expect(payload.scope).toBe('read write');
  });

  it('should preserve sub from parent token', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const rootToken = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|xyz',
      audience: 'https://rs.example.com',
    });

    const ftToken = await frenchToast(rootToken, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
    });

    const payload = decodeJwt(ftToken);
    expect(payload.sub).toBe('user|xyz');
  });

  it('should cap exp to parent exp', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const rootToken = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
      expiresIn: 60, // 60 seconds
    });

    const rootPayload = decodeJwt(rootToken);

    const ftToken = await frenchToast(rootToken, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
      expiresIn: 3600, // 1 hour — should be capped
    });

    const payload = decodeJwt(ftToken);
    expect(payload.exp).toBeLessThanOrEqual(rootPayload.exp as number);
  });

  it('should include cnf.jkt when nextHopPublicKey is provided', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const rootToken = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
    });

    const ftToken = await frenchToast(rootToken, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
      nextHopPublicKey: client2.publicKey,
    });

    const payload = decodeJwt(ftToken);
    const cnf = payload.cnf as { jkt: string };
    expect(cnf.jkt).toBe(client2.thumbprint);
  });

  it('should reject sub mismatch in extraClaims', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const rootToken = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
    });

    await expect(
      frenchToast(rootToken, {
        privateKey: client1.privateKey,
        issuer: 'https://client1.example.com/client_id.json',
        audience: 'https://rs.example.com',
        extraClaims: { sub: 'user|different' },
      }),
    ).rejects.toThrow('Subject does not match');
  });
});
