<p align="center">
  <img src="public/french-toast.png" alt="French Toast JWT" width="200" />
</p>

<h1 align="center">french-toast-jwt</h1>

<p align="center">Client-to-client delegation for OAuth 2.0 via JWT attenuation, re-signing, and DPoP proof of possession.</p>

## What is this?

OAuth 2.0 has no standard way for a client to delegate a subset of its authority to another client. french-toast-jwt fills that gap: a client takes its access token, re-signs it with its own key, adds claims, and passes it downstream -- building a verifiable delegation chain back to the original Authorization Server. The parent token is embedded in the JOSE header, keeping the payload clean at every layer. Each hop is DPoP-bound (RFC 9449), proving the presenter holds the key they claim.

The library is claim-agnostic. It doesn't interpret scopes, roles, or authorization details -- it just builds and verifies the chain. You decide what the claims mean.

```
Authorization Server ──(Token A)──> Client1 ──(Token B + DPoP)──> Client2 ──(Token C + DPoP)──> RS
```

See [SPEC.md](SPEC.md) for the full specification.

## Install

```bash
npm install french-toast-jwt
```

## Quick Start

### Create an attenuated token

```typescript
import { frenchToast } from 'french-toast-jwt';

const tokenB = await frenchToast(tokenA, {
  privateKey: client1PrivateKey,
  issuer: 'https://client1.example.com/client_id.json',
  audience: 'https://rs.example.com',
  extraClaims: { scope: 'read write' },
  nextHopPublicKey: client2PublicKey,
});
```

### Verify a token chain

```typescript
import { verify } from 'french-toast-jwt';

const result = await verify(tokenC, {
  resolveKey: async (issuer) => publicKeys[issuer],
  dpopProof,
  method: 'GET',
  url: 'https://rs.example.com/users',
});

// result.chain -- decoded tokens from outer to root
```

### Create and verify DPoP proofs

```typescript
import { createDPoPProof, verifyDPoPProof } from 'french-toast-jwt';

// Presenter creates a proof
const proof = await createDPoPProof({
  method: 'GET',
  url: 'https://rs.example.com/users',
  accessToken: tokenC,
  privateKey: presenterPrivateKey,
  publicKey: presenterPublicKey,
});

// Recipient verifies
await verifyDPoPProof(proof, tokenC, expectedJkt, 'GET', 'https://rs.example.com/users');
```

## Examples

### example1: Scope reduction at each hop

Pure scope attenuation with DPoP at every hop.

```
AS (scope: "read write delete")
  -> Client1 (scope: "read write")  + DPoP
  -> Client2 (scope: "read")        + DPoP
  -> RS verifies chain
```

```bash
npx tsx examples/example1.ts
```

### example2: Scope reduction + authorization_details

Same chain, but Client2 also adds `authorization_details` to restrict access to a specific API endpoint.

```
AS (scope: "read write delete")
  -> Client1 (scope: "read write")                    + DPoP
  -> Client2 (scope: "read", authz_details: /users)   + DPoP
  -> RS verifies chain
```

```bash
npx tsx examples/example2.ts
```

## API

### `frenchToast(parentToken, options)`

Re-sign a token with extra claims, embedding the parent in the JOSE header.

| Option | Type | Description |
|--------|------|-------------|
| `privateKey` | `CryptoKey \| Uint8Array` | Signer's private key |
| `issuer` | `string` | Issuer identifier |
| `audience` | `string` | Intended audience |
| `extraClaims` | `Record<string, unknown>` | Additional claims (optional) |
| `expiresIn` | `number` | Seconds until expiry, capped to parent (optional) |
| `nextHopPublicKey` | `CryptoKey \| Uint8Array` | Presenter's public key for `cnf.jkt` (optional) |
| `algorithm` | `string` | Signing algorithm, default `ES256` (optional) |

Returns: `Promise<string>` -- the signed FT-JWT.

### `verify(token, options)`

Verify an FT-JWT chain, optionally with DPoP.

| Option | Type | Description |
|--------|------|-------------|
| `resolveKey` | `(issuer: string) => Promise<CryptoKey \| Uint8Array \| string>` | Custom key resolver (optional, falls back to metadata discovery) |
| `dpopProof` | `string` | DPoP proof JWT (optional) |
| `method` | `string` | HTTP method (required if `dpopProof` is set) |
| `url` | `string` | Target URL (required if `dpopProof` is set) |

Returns: `Promise<VerifyResult>` with `valid: boolean` and `chain: ChainLink[]`.

### `createDPoPProof(options)`

Create a DPoP proof JWT per RFC 9449.

| Option | Type | Description |
|--------|------|-------------|
| `method` | `string` | HTTP method |
| `url` | `string` | Target URL |
| `accessToken` | `string` | The access token (hashed into `ath`) |
| `privateKey` | `CryptoKey \| Uint8Array` | Signer's private key |
| `publicKey` | `CryptoKey \| Uint8Array` | Signer's public key (for the `jwk` header) |
| `algorithm` | `string` | Signing algorithm, default `ES256` (optional) |

Returns: `Promise<string>` -- the signed DPoP proof JWT.

### `verifyDPoPProof(proof, accessToken, expectedJkt, method, url)`

Verify a DPoP proof against an access token's `cnf.jkt`.

Throws `DPoPVerificationError` on failure.

## Key Discovery

When `resolveKey` is not provided, the library discovers keys automatically via metadata documents:

- **Authorization Server Metadata** (RFC 8414) -- `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server`
- **Client ID Metadata Document** (draft-ietf-oauth-client-id-metadata-document)
- **Protected Resource Metadata** (RFC 9728) -- `/.well-known/oauth-protected-resource`

Each issuer in the chain must publish a metadata document with a `jwks_uri`.

## Stack

- [jose](https://github.com/panva/jose) -- JWT signing, verification, JWKS, JWK thumbprints
- [openid-client](https://github.com/panva/node-openid-client) -- OIDC discovery, token acquisition, DPoP support

## Development

```bash
npm install
npm test
```

## License

MIT
