import { describe, it, expect } from 'vitest';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { createDPoPProof, verifyDPoPProof } from '../src/dpop.js';
import { makeKeyPair, makeRootToken } from './helpers.js';

describe('DPoP', () => {
  it('should create a valid DPoP proof', async () => {
    const sender = await makeKeyPair();

    const proof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: 'fake-access-token',
      privateKey: sender.privateKey,
      publicKey: sender.publicKey,
    });

    const header = decodeProtectedHeader(proof);
    const payload = decodeJwt(proof);

    expect(header.typ).toBe('dpop+jwt');
    expect(header.jwk).toBeDefined();
    expect(payload.htm).toBe('GET');
    expect(payload.htu).toBe('https://rs.example.com/users');
    expect(payload.ath).toBeDefined();
    expect(payload.jti).toBeDefined();
  });

  it('should verify a valid DPoP proof', async () => {
    const sender = await makeKeyPair();

    const proof = await createDPoPProof({
      method: 'POST',
      url: 'https://rs.example.com/data',
      accessToken: 'my-token',
      privateKey: sender.privateKey,
      publicKey: sender.publicKey,
    });

    await expect(
      verifyDPoPProof(proof, 'my-token', sender.thumbprint, 'POST', 'https://rs.example.com/data'),
    ).resolves.toBeUndefined();
  });

  it('should reject DPoP proof with wrong thumbprint', async () => {
    const sender = await makeKeyPair();
    const other = await makeKeyPair();

    const proof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: 'tok',
      privateKey: sender.privateKey,
      publicKey: sender.publicKey,
    });

    await expect(
      verifyDPoPProof(proof, 'tok', other.thumbprint, 'GET', 'https://rs.example.com/users'),
    ).rejects.toThrow('thumbprint does not match');
  });

  it('should reject DPoP proof with wrong method', async () => {
    const sender = await makeKeyPair();

    const proof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: 'tok',
      privateKey: sender.privateKey,
      publicKey: sender.publicKey,
    });

    await expect(
      verifyDPoPProof(proof, 'tok', sender.thumbprint, 'POST', 'https://rs.example.com/users'),
    ).rejects.toThrow('htm mismatch');
  });

  it('should reject DPoP proof with wrong access token hash', async () => {
    const sender = await makeKeyPair();

    const proof = await createDPoPProof({
      method: 'GET',
      url: 'https://rs.example.com/users',
      accessToken: 'correct-token',
      privateKey: sender.privateKey,
      publicKey: sender.publicKey,
    });

    await expect(
      verifyDPoPProof(proof, 'wrong-token', sender.thumbprint, 'GET', 'https://rs.example.com/users'),
    ).rejects.toThrow('ath does not match');
  });
});
