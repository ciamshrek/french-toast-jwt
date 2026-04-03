export type KeyInput = CryptoKey | Uint8Array;

export const FT_TYPE = 'ft+jwt';
export const FT_PARENT_HEADER = 'ft_parent';

export interface FrenchToastOptions {
  /** Signer's private key */
  privateKey: KeyInput;
  /** Issuer identifier (must resolve to a metadata document with jwks_uri) */
  issuer: string;
  /** Intended audience */
  audience: string;
  /** Extra claims to add to the payload (claim-agnostic) */
  extraClaims?: Record<string, unknown>;
  /** Override expiry (seconds from now). Will be capped to parent's exp. */
  expiresIn?: number;
  /** Algorithm to sign with (default: ES256) */
  algorithm?: string;
  /** The next hop's public key — its JWK thumbprint goes into cnf.jkt */
  nextHopPublicKey?: KeyInput;
}

export interface DPoPOptions {
  /** HTTP method */
  method: string;
  /** Target URL */
  url: string;
  /** The access token (used to compute ath) */
  accessToken: string;
  /** Signer's private key */
  privateKey: KeyInput;
  /** Signer's public key (for the JWK header — avoids needing extractable private keys) */
  publicKey: KeyInput;
  /** Algorithm (default: ES256) */
  algorithm?: string;
}

export interface VerifyOptions {
  /** DPoP proof JWT string (from the DPoP header) */
  dpopProof?: string;
  /** HTTP method (required if dpopProof is provided) */
  method?: string;
  /** Target URL (required if dpopProof is provided) */
  url?: string;
  /**
   * Custom key resolver. If provided, bypasses metadata discovery.
   * Given an issuer, return the public key or JWKS URI.
   */
  resolveKey?: (issuer: string) => Promise<KeyInput | string>;
  /** Clock tolerance in seconds for iat/exp checks (default: 60) */
  clockTolerance?: number;
  /** Maximum chain depth (default: 10) */
  maxDepth?: number;
}

export interface ChainLink {
  /** Decoded JOSE header */
  header: Record<string, unknown>;
  /** Decoded payload */
  payload: Record<string, unknown>;
  /** Depth in the chain (0 = outermost) */
  depth: number;
}

export interface VerifyResult {
  /** Whether the full chain is valid */
  valid: boolean;
  /** Decoded tokens from outer to root */
  chain: ChainLink[];
}
