import { describe, it, expect, vi, afterEach } from 'vitest';
import { SignJWT } from 'jose';
import { frenchToast } from '../src/sign.js';
import { verify } from '../src/verify.js';
import { makeKeyPair, makeRootToken } from './helpers.js';

describe('verify temporal bounds', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should reject an expired outermost token', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    // Create a root token that expires in 1 second
    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
      expiresIn: 1,
    });

    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
    });

    // Fast-forward past expiry
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 120_000);

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    await expect(
      verify(tokenB, {
        resolveKey: async (issuer) => keys[issuer],
        clockTolerance: 0,
      }),
    ).rejects.toThrow(/expired|exp/i);
  });

  it('should reject a token with iat in the future', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    // Manually create a token with iat far in the future
    const futureIat = Math.floor(Date.now() / 1000) + 3600;
    const futureExp = futureIat + 3600;

    const tokenA = await new SignJWT({ scope: 'read' })
      .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
      .setIssuer('https://as.example.com')
      .setSubject('user|abc')
      .setAudience('https://client1.example.com/client_id.json')
      .setIssuedAt(futureIat)
      .setExpirationTime(futureExp)
      .sign(as.privateKey);

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
    };

    await expect(
      verify(tokenA, {
        resolveKey: async (issuer) => keys[issuer],
        clockTolerance: 0,
      }),
    ).rejects.toThrow(/iat.*future/i);
  });

  it('should enforce child iat >= parent iat', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
    });

    // Normal frenchToast always sets iat to now, which is >= parent iat
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
      'https://client1.example.com/client_id.json': client1.publicKey,
    };

    // This should pass -- child iat >= parent iat
    const result = await verify(tokenB, {
      resolveKey: async (issuer) => keys[issuer],
    });
    expect(result.valid).toBe(true);

    const childIat = result.chain[0].payload.iat as number;
    const parentIat = result.chain[1].payload.iat as number;
    expect(childIat).toBeGreaterThanOrEqual(parentIat);
  });

  it('should enforce child exp <= parent exp', async () => {
    const as = await makeKeyPair();
    const client1 = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
      expiresIn: 3600,
    });

    // frenchToast caps exp, so this should produce a valid chain
    const tokenB = await frenchToast(tokenA, {
      privateKey: client1.privateKey,
      issuer: 'https://client1.example.com/client_id.json',
      audience: 'https://rs.example.com',
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

  it('should accept tokens within clock tolerance', async () => {
    const as = await makeKeyPair();

    const tokenA = await makeRootToken({
      privateKey: as.privateKey,
      issuer: 'https://as.example.com',
      subject: 'user|abc',
      audience: 'https://rs.example.com',
      expiresIn: 60,
    });

    const keys: Record<string, CryptoKey> = {
      'https://as.example.com': as.publicKey,
    };

    // Should pass with default clock tolerance
    const result = await verify(tokenA, {
      resolveKey: async (issuer) => keys[issuer],
    });
    expect(result.valid).toBe(true);
  });
});
