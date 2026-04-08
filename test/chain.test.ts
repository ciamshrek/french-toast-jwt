import { describe, it, expect } from 'vitest';
import { decodeJwt } from 'jose';
import { frenchToast } from '../src/sign.js';
import { verify } from '../src/verify.js';
import { createDPoPProof } from '../src/dpop.js';
import { CHAIN_DELIMITER } from '../src/types.js';
import { makeKeyPair, makeRootToken } from './helpers.js';

const RS = 'https://rs.example.com';

describe('Chain verification (end-to-end)', () => {
  it('should verify a 3-token chain', async () => {
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

    const result = await verify([tokenC, tokenB, tokenA], {
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

  it('should verify chain passed as &-delimited string', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

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
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    const chainString = [tokenB, tokenA].join(CHAIN_DELIMITER);
    const result = await verify(chainString, {
      resolveKey: async (issuer) => keys[issuer],
    });

    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(2);
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

    const chainString = [tokenC, tokenB, tokenA].join(CHAIN_DELIMITER);

    // DPoP ath binds to the full chain string
    const dpopProof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: chainString,
      privateKey: rs.privateKey,
      publicKey: rs.publicKey,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    const result = await verify([tokenC, tokenB, tokenA], {
      resolveKey: async (issuer) => keys[issuer],
      dpopProof,
      method: 'GET',
      url: 'https://rs.example.com/users',
    });

    expect(result.valid).toBe(true);
    expect(result.chain).toHaveLength(3);
  });

  it('should reject chain with hash mismatch', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

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

    // Create a different root token
    const tokenA2 = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
      extraClaims: { different: true },
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    // Pass tokenB with wrong parent — hash won't match
    await expect(
      verify([tokenB, tokenA2], {
        resolveKey: async (issuer) => keys[issuer],
      }),
    ).rejects.toThrow('ft_parent hash does not match');
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
      verify([tokenB, tokenA], {
        resolveKey: async (issuer) => keys[issuer],
      }),
    ).rejects.toThrow('Signature verification failed');
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

    const result = await verify([tokenB, tokenA], {
      resolveKey: async (issuer) => keys[issuer],
    });

    expect(result.valid).toBe(true);
    const childExp = result.chain[0].payload.exp as number;
    const parentExp = result.chain[1].payload.exp as number;
    expect(childExp).toBeLessThanOrEqual(parentExp);
  });

  it('should reject chain with issuer not in allowedIssuers', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

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
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    // Only allow the AS — client1 is not allowed
    await expect(
      verify([tokenB, tokenA], {
        resolveKey: async (issuer) => keys[issuer],
        allowedIssuers: ['https://as.example.com'],
      }),
    ).rejects.toThrow('not in the allowed issuers list');
  });

  it('should pass chain when all issuers are in allowedIssuers', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

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
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    const result = await verify([tokenB, tokenA], {
      resolveKey: async (issuer) => keys[issuer],
      allowedIssuers: [
        'https://as.example.com',
        'https://client1.example.com/client_id.json',
      ],
    });

    expect(result.valid).toBe(true);
  });

  it('should enforce ft_iss — reject issuer not in parent ft_iss', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
    });

    // Client1 delegates but only allows client3 (not client2)
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      allowedIssuers: ['https://client3.example.com/client_id.json'],
    });

    // Client2 tries to delegate — not in ft_iss
    const tokenC = await frenchToast(tokenB, {
      privateKey: client2.privateKey,
      issuer: 'https://client2.example.com/client_id.json',
      audience: RS,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    await expect(
      verify([tokenC, tokenB, tokenA], {
        resolveKey: async (issuer) => keys[issuer],
      }),
    ).rejects.toThrow('not allowed by parent\'s ft_iss');
  });

  it('should enforce ft_iss — accept issuer in parent ft_iss', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
    });

    // Client1 delegates and allows client2
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      allowedIssuers: ['https://client2.example.com/client_id.json'],
    });

    const tokenC = await frenchToast(tokenB, {
      privateKey: client2.privateKey,
      issuer: 'https://client2.example.com/client_id.json',
      audience: RS,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    const result = await verify([tokenC, tokenB, tokenA], {
      resolveKey: async (issuer) => keys[issuer],
    });
    expect(result.valid).toBe(true);
  });

  it('should enforce ft_dep — reject when depth exceeded', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
    });

    // Client1 delegates with ft_dep: 0 (no further delegation allowed)
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      maxDepth: 0,
    });

    // Client2 tries to delegate — ft_dep is 0
    await expect(
      frenchToast(tokenB, {
        privateKey: client2.privateKey,
        issuer: 'https://client2.example.com/client_id.json',
        audience: RS,
      }),
    ).rejects.toThrow('does not allow further delegation');
  });

  it('should enforce ft_dep — accept when depth allows', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();
    const client2 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: RS,
    });

    // Client1 delegates with ft_dep: 1 (one more delegation allowed)
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: RS,
      maxDepth: 1,
    });

    // Client2 can delegate (ft_dep was 1, now becomes 0)
    const tokenC = await frenchToast(tokenB, {
      privateKey: client2.privateKey,
      issuer: 'https://client2.example.com/client_id.json',
      audience: RS,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
      'https://client2.example.com/client_id.json': client2.publicKey,
    };

    const result = await verify([tokenC, tokenB, tokenA], {
      resolveKey: async (issuer) => keys[issuer],
    });
    expect(result.valid).toBe(true);
  });
});
