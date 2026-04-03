import { describe, it, expect } from 'vitest';
import { decodeJwt } from 'jose';
import { frenchToast } from '../src/sign.js';
import { verify } from '../src/verify.js';
import { createDPoPProof } from '../src/dpop.js';
import { makeKeyPair, makeRootToken } from './helpers.js';

const RS = 'https://rs.example.com';

describe('Chain verification (end-to-end)', () => {
  it('should verify a 3-token chain with resolveKey', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc123',
      audience: RS,
      extraClaims: { scope: 'read write delete' },
      nextHopThumbprint: client1.thumbprint,
    });

    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      extraClaims: { scope: 'read write' },
      nextHopPublicKey: client2.publicKey,
    });

    const tokenC = await frenchToast(tokenB, {
      privateKey: client2.privateKey,
      issuer: 'https://client2.example.com/client_id.json',
      audience: RS,
      extraClaims: { scope: 'read' },
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    const result = await verify(tokenC, {
      resolveKey: async (issuer) => keys[issuer],
    });

    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(3);

    expect(result.chain[0].payload.iss).toBe('https://client2.example.com/client_id.json');
    expect(result.chain[0].payload.scope).toBe('read');
    expect(result.chain[0].depth).toBe(0);

    expect(result.chain[1].payload.iss).toBe('https://client1.example.com/client_id.json');
    expect(result.chain[1].payload.scope).toBe('read write');
    expect(result.chain[1].depth).toBe(1);

    expect(result.chain[2].payload.iss).toBe('https://as.example.com');
    expect(result.chain[2].payload.scope).toBe('read write delete');
    expect(result.chain[2].depth).toBe(2);

    // aud is the RS throughout
    for (const link of result.chain) {
      expect(link.payload.aud).toBe(RS);
    }
  });

  it('should verify chain + DPoP proof', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();
    const rs = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
      extraClaims: { scope: 'read write delete' },
      nextHopThumbprint: client1.thumbprint,
    });

    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      extraClaims: { scope: 'read write' },
      nextHopPublicKey: client2.publicKey,
    });

    const tokenC = await frenchToast(tokenB, {
      privateKey: client2.privateKey,
      issuer: 'https://client2.example.com/client_id.json',
      audience: RS,
      extraClaims: { scope: 'read' },
      nextHopPublicKey: rs.publicKey,
    });

    const dpopProof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: tokenC,
      privateKey: rs.privateKey,
      publicKey: rs.publicKey,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    const result = await verify(tokenC, {
      resolveKey: async (issuer) => keys[issuer],
      dpopProof,
      method: 'GET',
      url: 'https://rs.example.com/users',
    });

    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(3);
  });

  it('should reject chain with subject mismatch', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const rootGood = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|good',
      audience: RS,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    // Normal chain should work — sub matches throughout
    const normalToken = await frenchToast(rootGood, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
    });

    const result = await verify(normalToken, {
      resolveKey: async (issuer) => keys[issuer],
    });
    expect(result.valid).toBe(true);
    expect(result.chain[0].payload.sub).toBe('user|good');
    expect(result.chain[1].payload.sub).toBe('user|good');
  });

  it('should reject chain with expiry violation', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
      expiresIn: 3600,
    });

    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      expiresIn: 30,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    const result = await verify(tokenB, {
      resolveKey: async (issuer) => keys[issuer],
    });

    expect(result.valid).toBe(true);
    const childExp = result.chain[0].payload.exp as number;
    const parentExp = result.chain[1].payload.exp as number;
    expect(childExp).toBeLessThanOrEqual(parentExp);
  });

  it('should reject chain with wrong key', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const wrongKey = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
    });

    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': wrongKey.publicKey,
    };

    await expect(
      verify(tokenB, {
        resolveKey: async (issuer) => keys[issuer],
      }),
    ).rejects.toThrow('Signature verification failed');
  });
});
