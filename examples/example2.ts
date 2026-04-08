/**
 * example2: Scope reduction + authorization_details + DPoP at every hop
 *
 * AS (scope: "read write delete")
 *   -> Client1 (scope: "read write")       + DPoP proof from Client1
 *   -> Client2 (scope: "read" + authz_det) + DPoP proof from Client2
 *   -> Resource Server verifies chain + DPoP
 *
 * Key discovery uses:
 *   - AS Metadata (RFC 8414) for the Authorization Server
 *   - Client ID Metadata Document (CIMD) for Client1 and Client2
 */
import { generateKeyPair, exportJWK, calculateJwkThumbprint, SignJWT, decodeJwt } from 'jose';
import { delegate, verify, createDPoPProof, verifyDPoPProof, CHAIN_DELIMITER } from '../src/index.js';
import { createDiscoveryResolver } from './metadata.js';

async function main() {
  const as = await generateKeyPair('ES256');
  const client1 = await generateKeyPair('ES256');
  const client2 = await generateKeyPair('ES256');

  const client1Thumbprint = await calculateJwkThumbprint(await exportJWK(client1.publicKey), 'sha256');
  const client2Thumbprint = await calculateJwkThumbprint(await exportJWK(client2.publicKey), 'sha256');

  // ─── Step 1: Authorization Server issues token A (DPoP-bound to Client1) ───
  const tokenA = await new SignJWT({ scope: 'read write delete', cnf: { jkt: client1Thumbprint } })
    .setProtectedHeader({ alg: 'ES256', typ: 'ft+jwt' })
    .setIssuer('https://as.example.com')
    .setSubject('user|abc123')
    .setAudience('https://rs.example.com')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(as.privateKey);

  console.log('=== Step 1: AS issues Token A ===');
  console.log(`Token A bound to Client1 (cnf.jkt: ${client1Thumbprint.slice(0, 12)}...)`);
  console.log();

  // ─── Step 2: Client1 presents Token A to Client2 ───
  const dpopProofB = await createDPoPProof({
    method: 'POST',
    url: 'https://client2.example.com/process',
    accessToken: tokenA,
    privateKey: client1.privateKey,
    publicKey: client1.publicKey,
  });

  console.log('=== Step 2: Client1 -> Client2 ===');
  console.log('HTTP Request:');
  console.log(`  POST /process HTTP/1.1`);
  console.log(`  Host: client2.example.com`);
  console.log(`  Authorization: DPoP ${tokenA.slice(0, 30)}...`);
  console.log(`  DPoP: ${dpopProofB.slice(0, 30)}...`);
  console.log();

  // Client2 verifies DPoP on Token A
  const tokenACnf = (decodeJwt(tokenA).cnf as { jkt: string });
  await verifyDPoPProof(dpopProofB, tokenA, tokenACnf.jkt, 'POST', 'https://client2.example.com/process');
  console.log('  ✔ Client2 verified Client1 DPoP proof');

  // Client1 attenuates: scope "read write", bind to Client2
  const tokenB = await delegate(tokenA, {
    privateKey: client1.privateKey,
    issuer: 'https://client1.example.com/client_id.json',
    audience: 'https://rs.example.com',
    extraClaims: { scope: 'read write' },
    nextHopPublicKey: client2.publicKey,
  });

  console.log(`  Token B: scope "read write", bound to Client2 (cnf.jkt: ${client2Thumbprint.slice(0, 12)}...)`);
  console.log();

  // ─── Step 3: Client2 attenuates and presents to Resource Server ───
  const tokenC = await delegate(tokenB, {
    privateKey: client2.privateKey,
    issuer: 'https://client2.example.com/client_id.json',
    audience: 'https://rs.example.com',
    extraClaims: {
      scope: 'read',
      authorization_details: [{
        type: 'api_endpoint',
        actions: ['read'],
        locations: ['/users'],
      }],
    },
    nextHopPublicKey: client2.publicKey,
  });

  // Build the chain string: outermost & ... & root
  const chainString = [tokenC, tokenB, tokenA].join(CHAIN_DELIMITER);

  const dpopProofC = await createDPoPProof({
    method: 'GET',
    url: 'https://rs.example.com/users',
    accessToken: chainString,
    privateKey: client2.privateKey,
    publicKey: client2.publicKey,
  });

  console.log('=== Step 3: Client2 -> Resource Server ===');
  console.log('HTTP Request:');
  console.log(`  GET /users HTTP/1.1`);
  console.log(`  Host: rs.example.com`);
  console.log(`  Authorization: DPoP ${tokenC.slice(0, 20)}...&${tokenB.slice(0, 20)}...&${tokenA.slice(0, 20)}...`);
  console.log(`  DPoP: ${dpopProofC.slice(0, 30)}...`);
  console.log();

  // ─── Step 4: Resource Server verifies the full chain + DPoP ───
  console.log('=== Step 4: Resource Server verifies ===');
  console.log();

  const resolveKey = createDiscoveryResolver({
    'https://as.example.com': {
      publicKey: as.publicKey,
      metadataType: 'as-metadata',
    },
    'https://client1.example.com/client_id.json': {
      publicKey: client1.publicKey,
      metadataType: 'cimd',
    },
    'https://client2.example.com/client_id.json': {
      publicKey: client2.publicKey,
      metadataType: 'cimd',
    },
  });

  const result = await verify([tokenC, tokenB, tokenA], {
    resolveKey,
    dpopProof: dpopProofC,
    method: 'GET',
    url: 'https://rs.example.com/users',
  });

  console.log('  ✔ DPoP proof verified (Client2 holds bound key)');
  console.log('  ✔ Full chain verified');
  console.log();

  console.log('=== Chain ===');
  for (const link of result.chain) {
    const p = link.payload;
    const parts = [`iss: ${p.iss}`, `scope: "${p.scope}"`];
    if (p.authorization_details) parts.push(`authorization_details: ${JSON.stringify(p.authorization_details)}`);
    console.log(`  [${link.depth}] ${parts.join(', ')}`);
  }

  console.log();
  console.log('=== Raw Tokens ===');
  console.log();
  console.log('Token A (root):');
  console.log(tokenA);
  console.log();
  console.log('Token B (Client1 -> Client2):');
  console.log(tokenB);
  console.log();
  console.log('Token C (Client2 -> RS):');
  console.log(tokenC);
  console.log();
  console.log('=== Authorization Header ===');
  console.log(`DPoP ${chainString}`);
}

main().catch(console.error);
