/**
 * Simulated metadata discovery for examples.
 *
 * In production, the library fetches real metadata documents from
 * well-known endpoints. This helper emulates that process with
 * logging, showing which document type is used for each participant:
 *
 *   - Authorization Server Metadata (RFC 8414)
 *   - Client ID Metadata Document (CIMD)
 *   - Protected Resource Metadata (RFC 9728)
 */
import { exportJWK } from 'jose';

interface Participant {
  publicKey: CryptoKey;
  /** Which metadata document type this participant publishes */
  metadataType: 'as-metadata' | 'cimd' | 'prm';
}

/**
 * Build a resolveKey function that simulates metadata discovery with logging.
 */
export function createDiscoveryResolver(participants: Record<string, Participant>) {
  return async (issuer: string): Promise<CryptoKey> => {
    const participant = participants[issuer];
    if (!participant) {
      throw new Error(`Unknown issuer: ${issuer}`);
    }

    const publicJwk = await exportJWK(participant.publicKey);
    const kid = publicJwk.x ? (publicJwk.x as string).slice(0, 8) : 'key-1';

    switch (participant.metadataType) {
      case 'as-metadata': {
        const metadataUrl = `${issuer}/.well-known/oauth-authorization-server`;
        const jwksUri = `${issuer}/jwks`;

        console.log(`  [discovery] Issuer: ${issuer}`);
        console.log(`    -> GET ${metadataUrl}`);
        console.log(`    <- 200 OK (Authorization Server Metadata - RFC 8414)`);
        console.log(`       {`);
        console.log(`         "issuer": "${issuer}",`);
        console.log(`         "jwks_uri": "${jwksUri}",`);
        console.log(`         "token_endpoint": "${issuer}/oauth/token",`);
        console.log(`         "dpop_signing_alg_values_supported": ["ES256"]`);
        console.log(`       }`);
        console.log(`    -> GET ${jwksUri}`);
        console.log(`    <- 200 OK (JWK Set)`);
        console.log(`       { "keys": [{ "kty": "${publicJwk.kty}", "crv": "${publicJwk.crv}", "kid": "${kid}...", "use": "sig" }] }`);
        console.log(`    -> Signature verified with kid="${kid}..."`);
        console.log();
        break;
      }

      case 'cimd': {
        // CIMD: the issuer IS the direct URL to the metadata document
        const baseUrl = new URL(issuer).origin;
        const jwksUri = `${baseUrl}/jwks`;

        console.log(`  [discovery] Issuer: ${issuer}`);
        console.log(`    -> GET ${issuer}  (direct CIMD URL)`);
        console.log(`    <- 200 OK (Client ID Metadata Document - draft-ietf-oauth-client-id-metadata-document)`);
        console.log(`       {`);
        console.log(`         "client_id": "${issuer}",`);
        console.log(`         "client_name": "${new URL(issuer).hostname}",`);
        console.log(`         "jwks_uri": "${jwksUri}",`);
        console.log(`         "token_endpoint_auth_method": "private_key_jwt",`);
        console.log(`         "dpop_bound_access_tokens": true`);
        console.log(`       }`);
        console.log(`    -> GET ${jwksUri}`);
        console.log(`    <- 200 OK (JWK Set)`);
        console.log(`       { "keys": [{ "kty": "${publicJwk.kty}", "crv": "${publicJwk.crv}", "kid": "${kid}...", "use": "sig" }] }`);
        console.log(`    -> Signature verified with kid="${kid}..."`);
        console.log();
        break;
      }

      case 'prm': {
        const metadataUrl = `${issuer}/.well-known/oauth-protected-resource`;
        const jwksUri = `${issuer}/jwks`;

        console.log(`  [discovery] Issuer: ${issuer}`);
        console.log(`    -> GET ${metadataUrl}`);
        console.log(`    <- 200 OK (Protected Resource Metadata - RFC 9728)`);
        console.log(`       {`);
        console.log(`         "resource": "${issuer}",`);
        console.log(`         "jwks_uri": "${jwksUri}",`);
        console.log(`         "authorization_servers": ["https://as.example.com"],`);
        console.log(`         "dpop_signing_alg_values_supported": ["ES256"]`);
        console.log(`       }`);
        console.log(`    -> GET ${jwksUri}`);
        console.log(`    <- 200 OK (JWK Set)`);
        console.log(`       { "keys": [{ "kty": "${publicJwk.kty}", "crv": "${publicJwk.crv}", "kid": "${kid}...", "use": "sig" }] }`);
        console.log(`    -> Signature verified with kid="${kid}..."`);
        console.log();
        break;
      }
    }

    return participant.publicKey;
  };
}
