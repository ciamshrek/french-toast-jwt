import { createRemoteJWKSet } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { KeyDiscoveryError } from './errors.js';

// Cache JWKS fetchers by issuer to avoid repeated discovery
const jwksCache = new Map<string, JWTVerifyGetKey>();

/**
 * Well-known paths to try for metadata discovery, in order:
 * 1. OpenID Connect discovery
 * 2. OAuth Authorization Server Metadata (RFC 8414)
 * 3. Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document)
 * 4. OAuth Protected Resource Metadata (RFC 9728)
 */
const WELL_KNOWN_PATHS = [
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-client',
  '/.well-known/oauth-protected-resource',
];

interface Metadata {
  jwks_uri?: string;
  jwks?: { keys: Array<Record<string, unknown>> };
}

async function tryFetchMetadata(url: string): Promise<Metadata | null> {
  try {
    const response = await fetch(url);
    if (!response.ok) return null;
    return (await response.json()) as Metadata;
  } catch {
    return null;
  }
}

/**
 * Discover and return a JWKS key resolver for the given issuer.
 *
 * If the issuer URL looks like a direct CIMD URL (e.g., ends with .json
 * or a non-well-known path), try fetching it directly first. Otherwise,
 * try well-known endpoints.
 */
export async function discoverKeys(issuer: string): Promise<JWTVerifyGetKey> {
  const cached = jwksCache.get(issuer);
  if (cached) return cached;

  // If the issuer looks like a direct document URL (CIMD), try fetching it directly
  const parsed = new URL(issuer);
  const isDirectUrl = parsed.pathname !== '/' && !parsed.pathname.startsWith('/.well-known');

  if (isDirectUrl) {
    const metadata = await tryFetchMetadata(issuer);
    if (metadata?.jwks_uri) {
      const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
      jwksCache.set(issuer, jwks);
      return jwks;
    }
  }

  // Fall back to well-known discovery
  const baseUrl = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  for (const path of WELL_KNOWN_PATHS) {
    const metadata = await tryFetchMetadata(`${baseUrl}${path}`);
    if (metadata?.jwks_uri) {
      const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
      jwksCache.set(issuer, jwks);
      return jwks;
    }
  }

  throw new KeyDiscoveryError(issuer, 'No metadata endpoint found with jwks_uri');
}

/**
 * Clear the JWKS cache (useful for testing).
 */
export function clearKeyCache(): void {
  jwksCache.clear();
}
