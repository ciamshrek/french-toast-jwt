# French Toast JWT (FT-JWT)

## Token Attenuation through Re-Signing and Claim Layering

### Authors

-  Aaron Parecki
-  Abhishek Hingnikar

### Status of This Document

This document describes the French Toast JWT (FT-JWT) token format and
processing rules for JWT-based token attenuation with proof of possession.

### Abstract

This specification defines a mechanism for attenuating JSON Web Tokens
(JWTs) by re-signing them with additional claims while preserving a
verifiable chain back to the original issuer.  Each token in the chain
references its parent via a SHA-256 hash in the JOSE header.  The full
chain is transmitted as an ampersand-delimited sequence of tokens in
the Authorization header. Tokens are bound to their presenter via
Demonstrating Proof of Possession (DPoP) per RFC 9449.

### Table of Contents

1. Introduction
2. Terminology
3. Token Format
4. Token Issuance
5. Proof of Possession
6. Chain Format
7. Chain Verification
8. Key Discovery
9. HTTP Usage
10. Security Considerations
11. Normative References
12. Acknowledgements

---

## 1.  Introduction

OAuth 2.0 defines a model where an Authorization Server issues access
tokens to clients.  However, there is no standard mechanism for a
client to delegate a subset of its authority.

Today, this is typically handled by forwarding the original access
token as-is, granting the downstream party the full authority of the
original client. Alternatively, the downstream party obtains its own
token through a separate authorization grant, which requires
out-of-band coordination and does not preserve the delegation chain.

FT-JWT addresses this gap by enabling local delegation. The bearer 
re-signs its access token with its own key, adding claims that layer 
additional constraints, while referencing the parent token via a 
hash in the JOSE protected header.  The full chain of tokens is 
transmitted together, and can be verified back to the original issuer,
with each hop's identity and claims preserved.

Each token in the chain is DPoP-bound, ensuring that only the intended
presenter can use it.  Key discovery leverages existing metadata
documents (Authorization Server Metadata, Client ID Metadata 
Documents), requiring no additional infrastructure.

## 2.  Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

**FT-JWT**
:  A JWT whose "typ" header parameter is "ft+jwt".  All tokens in
   an FT-JWT chain, including the root token, use this type.

**Parent Token**
:  The token that was attenuated to produce the current FT-JWT.
   Referenced by a SHA-256 hash in the "ft_parent" header parameter.

**Root Token**
:  The original JWT issued by the Authorization Server.  It has no
   "ft_parent" header parameter and is the last token in the chain.

**Chain**
:  The ordered sequence of tokens from the outermost FT-JWT to the
   root token, transmitted as an ampersand-delimited string.  Each
   non-root token's "ft_parent" hash binds it to the next token in
   the sequence.

**Presenter**
:  The entity that presents a token to a downstream service.  The
   token's "cnf.jkt" claim identifies the presenter's key.

## 3.  Token Format

### 3.1.  JOSE Header

All tokens in the chain MUST use "typ" value "ft+jwt".

A non-root FT-JWT MUST include the following header parameters:

```json
{
  "alg": "ES256",
  "typ": "ft+jwt",
  "ft_parent": "<base64url(SHA-256(parent token))>",
  "ft_iss": ["https://sub-agent.example.com/client_id.json"],
  "ft_dep": 3
}
```

A root token MUST include "alg" and "typ".  It MAY include "ft_iss"
and "ft_dep" to constrain delegation from the outset.  It MUST NOT
include "ft_parent":

```json
{
  "alg": "ES256",
  "typ": "ft+jwt",
  "ft_iss": ["https://agent.example.com/client_id.json"],
  "ft_dep": 5
}
```

**alg**
:  The algorithm used to sign this token.  Any algorithm supported by
   JWS (RFC 7515) MAY be used.

**typ**
:  MUST be "ft+jwt".

**ft_parent**
:  MUST contain the base64url encoding of the SHA-256 hash of the
   parent token's compact serialization.  MUST NOT be present on the
   root token.

**ft_iss** (OPTIONAL)
:  An array of issuer identifiers (strings) that are permitted to
   appear as the "iss" claim in child tokens.  If present on a
   parent token, any child token's "iss" MUST be a member of this
   array.  Each hop MAY reduce this array (remove entries) but MUST
   NOT add entries that were not in the parent's "ft_iss".  If
   absent, any issuer is accepted.

**ft_dep** (OPTIONAL)
:  A non-negative integer indicating the maximum remaining delegation
   depth.  A value of 0 means no further delegation is permitted.
   When creating a child token from a parent with "ft_dep", the child
   MUST set "ft_dep" to a value strictly less than the parent's
   "ft_dep".  If the parent's "ft_dep" is 0, delegation MUST be
   refused.  If absent, delegation depth is unbound.  A default of 5
   is RECOMMENDED when setting "ft_dep" for the first time.

### 3.2.  Payload

The payload is a standard JWT Claims Set (RFC 7519 Section 4) with the
following requirements:

```json
{
  "iss": "https://client2.example.com/client_id.json",
  "sub": "user|abc123",
  "aud": "https://rs.example.com",
  "exp": 1712099000,
  "iat": 1712096420,
  "cnf": {
    "jkt": "<JWK Thumbprint of presenter's key>"
  }
}
```

**iss** (REQUIRED)
:  The issuer of this token.  For clients, this MUST be the full
   URL of the Client ID Metadata Document (e.g.,
   "https://client1.example.com/client_id.json") as defined in
   draft-ietf-oauth-client-id-metadata-document.  For the
   Authorization Server, this is the issuer identifier per RFC 8414.
   In both cases, dereferencing the "iss" value yields a metadata
   document containing a "jwks_uri" or "jwks" parameter.

**sub** (REQUIRED)
:  The subject.  MUST match the "sub" claim of the parent token.

**aud** (REQUIRED)
:  The protected resource this token grants access to.  MUST match
   the "aud" claim of the parent token.  The audience does not change
   across the delegation chain -- it always identifies the resource
   server, not intermediary clients.

**exp** (REQUIRED)
:  Expiration time.  MUST be less than or equal to the "exp" claim
   of the parent token.

**iat** (REQUIRED)
:  Issued-at time.  MUST NOT be in the future (subject to clock
   tolerance).  MUST be greater than or equal to the parent token's
   "iat" (a child cannot claim to have been issued before its parent).

**cnf** (REQUIRED)
:  Confirmation claim per RFC 7800.  The "jkt" member MUST contain
   the JWK Thumbprint (RFC 7638) of the presenter's public key,
   computed using SHA-256.

Additional claims MAY be included.  The specification imposes no
semantics on these claims; interpretation is left to the verifier.

### 3.3.  Constraints

1.  "sub" MUST match the root token's "sub" at every level of the
    chain.

2.  "aud" MUST match the root token's "aud" at every level of the
    chain.

3.  "exp" MUST NOT exceed the parent token's "exp".

4.  "iat" MUST NOT be before the parent token's "iat".

5.  "iat" MUST be less than or equal to "exp".

6.  "iat" MUST NOT be in the future (subject to clock tolerance).

7.  "exp" MUST NOT be in the past (subject to clock tolerance).

8.  "ft_parent" MUST contain the base64url-encoded SHA-256 hash of
    the parent token's compact serialization.

9.  If the parent token's "ft_iss" is present, the child token's
    "iss" MUST be a member of "ft_iss".  The child's "ft_iss", if
    set, MUST be a subset of the parent's "ft_iss".

10. If the parent token's "ft_dep" is present and is 0, delegation
    MUST be refused.  If "ft_dep" is present and greater than 0,
    the child's "ft_dep" MUST be strictly less than the parent's.

11. Extra claims are opaque to the specification.  The verifier is
    responsible for interpreting them.

## 4.  Token Issuance

### 4.1.  Creating an FT-JWT

To create an FT-JWT from a parent token, the issuer MUST:

1.  Decode the parent token's payload (without verifying the
    signature; the issuer is assumed to have already verified
    the token it received).

2.  Construct a new JWT Claims Set:
    a.  Set "sub" to the parent token's "sub" value.
    b.  Set "iss" to the issuer's own identifier.
    c.  Set "aud" to the parent token's "aud" value.
    d.  Set "iat" to the current time.
    e.  Set "exp" to the desired expiration, capped to the parent
        token's "exp".
    f.  Set "cnf.jkt" to the JWK Thumbprint of the presenter's
        public key.
    g.  Include any additional claims.

3.  Construct the JOSE header:
    a.  Set "alg" to the signing algorithm.
    b.  Set "typ" to "ft+jwt".
    c.  Set "ft_parent" to base64url(SHA-256(parent token compact
        serialization)).

4.  Sign the token with the issuer's private key.  This key MUST
    correspond to a public key published in the issuer's metadata
    document (via "jwks_uri" or inline "jwks"), so that verifiers
    can discover and validate the signature.

### 4.2.  Presenter Binding

The "cnf.jkt" claim binds the token to the entity that will present
it.  This is the entity that will include the token in an HTTP request
alongside a DPoP proof.

When creating an FT-JWT:

-  If the issuer will forward the token itself, "cnf.jkt" MUST be
   the thumbprint of the issuer's own public key.

-  If the issuer is creating the token for a different presenter,
   "cnf.jkt" MUST be the thumbprint of that presenter's public key.

## 5.  Proof of Possession

FT-JWT uses Demonstrating Proof of Possession (DPoP) per RFC 9449
without modification.  Each token in the chain includes a "cnf.jkt"
claim binding it to the presenter's key.  When presenting an FT-JWT,
the presenter MUST include a DPoP proof as defined in RFC 9449.

The DPoP proof's "ath" (access token hash) claim MUST be computed
over the full chain string (the ampersand-delimited sequence of
tokens), not just the outermost token.

Refer to RFC 9449 for DPoP proof creation and verification procedures.

## 6.  Chain Format

### 6.1.  Chain String

The full chain of tokens is represented as an ampersand-delimited
string, ordered from latest token to root token:

```
<latest-token>&<intermediate-token>&...&<root-token>
```

For example, a 3-hop chain:

```
<tokenC>&<tokenB>&<tokenA>
```

Where tokenC is the latest (most attenuated) token and tokenA is
the root token issued by the Authorization Server.

### 6.2.  Hash Binding

Each non-root token in the chain MUST include an "ft_parent" header
parameter containing:

```
ft_parent = base64url(SHA-256(ASCII(next token in chain)))
```

This binds each token to its parent by hash.  The verifier confirms
that the hash in each token's header matches the SHA-256 hash of the
next token in the chain string.

This design keeps individual tokens compact (no embedded parents)
while maintaining cryptographic binding between chain members.

## 7.  Chain Verification

### 7.1.  Verification Procedure

To verify an FT-JWT chain, the verifier MUST perform the following
steps:

1.  Parse the chain: split the chain string on "&" to produce an
    ordered array of token strings.  Reject if the chain is empty
    or exceeds the maximum depth (RECOMMENDED: 10).

2.  Verify hash binding: for each non-root token at index i,
    confirm that its "ft_parent" header value equals
    base64url(SHA-256(token at index i+1)).  Reject on mismatch.

3.  Verify from root to latest: starting from the root token
    (last in the array) and working toward the latest token:
    a.  Verify the token's signature using the issuer's public key,
        discovered per Section 8.
    b.  Confirm that "exp" is present and not in the past.
    c.  Confirm that "iat" is present and not in the future.
    d.  Confirm that "iat" <= "exp".
    e.  For non-root tokens, confirm:
        - "exp" does not exceed the parent token's "exp".
        - "iat" is not before the parent token's "iat".
        - "sub" matches the root token's "sub".
        - "aud" matches the root token's "aud".
        - If the parent's "ft_iss" is present, confirm the child's
          "iss" is in the list.
        - If the parent's "ft_dep" is present, confirm it is > 0,
          and that the child's "ft_dep" (if present) is strictly
          less than the parent's.
        - If the child has "ft_iss", confirm it is a subset of the
          parent's "ft_iss" (if present).

4.  Verify DPoP: if a DPoP proof is present, verify it per RFC 9449.
    The "ath" claim MUST match the SHA-256 hash of the full chain
    string.  DPoP verification occurs after all signatures in the
    chain have been verified.

5.  Return the chain of decoded tokens (outermost to root).

### 7.2.  Verification Output

Upon successful verification, the verifier has an ordered list of
decoded tokens from the outermost FT-JWT (depth 0) to the root
token (maximum depth).  For example, a 3-hop chain yields:

    Depth 0:  iss=client2  (outermost FT-JWT)
    Depth 1:  iss=client1
    Depth 2:  iss=AS        (root token)

The verifier is responsible for interpreting the claims at each depth
and enforcing its own authorization policy.

## 8.  Key Discovery

Keys for each issuer in the chain are discovered automatically via
metadata documents.  No manual key configuration is required.

Each participant in the chain MUST publish one of the following
metadata documents:

-  **Authorization Server Metadata** (RFC 8414) at
   "/.well-known/oauth-authorization-server" -- for the Authorization
   Server (root token issuer).

-  **Client ID Metadata Document**
   (draft-ietf-oauth-client-id-metadata-document) -- for clients in
   the chain.  The "iss" claim is the direct URL to the document.

The metadata document MUST contain a "jwks_uri" parameter pointing to
a JWK Set (RFC 7517), or an inline "jwks" parameter.

### 8.1.  Discovery Procedure

For each issuer in the chain, the verifier:

1.  Extracts the "iss" claim from the token.

2.  If the "iss" value is a direct URL to a document (e.g., ends
    with a non-well-known path like "/client_id.json"), fetches
    it directly as a Client ID Metadata Document.

3.  Otherwise, attempts well-known endpoints in order:
    a.  "{iss}/.well-known/openid-configuration"
    b.  "{iss}/.well-known/oauth-authorization-server"
    c.  "{iss}/.well-known/oauth-client"

4.  Parses the "jwks_uri" from the metadata response.

5.  Fetches the JWK Set from the "jwks_uri".

6.  Verifies the token's signature against the keys in the JWK Set.

Implementations SHOULD cache JWK Sets per issuer to avoid redundant
network requests.

## 9.  HTTP Usage

### 9.1.  Sending an FT-JWT Chain

When sending an FT-JWT chain in an HTTP request, the sender MUST:

1.  Include the chain in the Authorization header using the DPoP
    scheme.  The chain is the ampersand-delimited sequence of tokens,
    outermost first:

    ```
    Authorization: DPoP <tokenC>&<tokenB>&<tokenA>
    ```

2.  Include a DPoP proof in the DPoP header:

    ```
    DPoP: <dpop-proof-jwt>
    ```

### 9.2.  Example: Single Delegation (Agent to Sub-Agent)

```http
GET /resources HTTP/1.1
Host: rs.example.com
Authorization: DPoP <tokenB>&<tokenA>
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0...
```

The Resource Server splits the Authorization header value on "&"
to obtain the chain:

    Token B (outermost):
      Header: { "alg": "ES256", "typ": "ft+jwt", "ft_parent": "<hash-of-tokenA>" }
      Payload: { "iss": "https://agent.example.com/client_id.json", "scope": "read" }

    Token A (root):
      Header: { "alg": "ES256", "typ": "ft+jwt" }
      Payload: { "iss": "https://as.example.com", "scope": "read write delete" }

Verification:
1.  Confirm ft_parent hash of Token B matches SHA-256(Token A).
2.  Verify Token A signature (AS key, via AS Metadata).
3.  Verify Token B signature (Agent key, via CIMD).
4.  Check sub, aud, exp, iat constraints.
5.  Verify DPoP proof (ath = SHA-256(full chain string)).

### 9.3.  Example: Two Delegations

```http
GET /users HTTP/1.1
Host: rs.example.com
Authorization: DPoP <tokenC>&<tokenB>&<tokenA>
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0...
```

    Token C: iss=client2, scope=read, authorization_details=[...]
    Token B: iss=client1, scope=read write
    Token A: iss=AS, scope=read write delete

## 10.  Security Considerations

### 10.1.  Token Replay

DPoP binding mitigates token replay.  Each token's "cnf.jkt" claim
binds it to a specific presenter, and the DPoP proof demonstrates
possession of the corresponding private key at the time of the
request.

### 10.2.  Scope Escalation

This specification does not enforce scope reduction.  It is the
responsibility of the verifier to inspect the claims at each level
of the chain and enforce that privileges are not escalated.
Implementations SHOULD compare claims across the chain and reject
tokens where a child claims broader access than its parent.

### 10.3.  Chain Depth

Implementations MUST impose a maximum chain depth to prevent
denial-of-service.  A depth limit of 10 is RECOMMENDED.

### 10.4.  Chain Size

The chain is transmitted as an ampersand-delimited string in the
Authorization header.  Each token in the chain is independent (no
embedded parents), so the total size grows linearly with chain
depth.  Implementations SHOULD be aware of HTTP header size limits
(typically 8KB).

### 10.5.  Key Material

Private keys used for signing MUST NOT be extractable.  The DPoP
proof requires only the public key in its header; implementations
MUST accept the public key as a separate parameter rather than
deriving it from the private key.

### 10.6.  Clock Skew

When verifying "exp" and "iat" constraints across the chain,
implementations SHOULD allow for reasonable clock skew between
participants.

### 10.7.  Key Discovery and SSRF

Automatic key discovery resolves metadata documents and JWKS URIs
derived from the "iss" claim of each token in the chain.  Since
"iss" is attacker-controlled in child tokens, this creates a
server-side request forgery (SSRF) risk: a malicious token can
direct the verifier to fetch from internal network addresses.

Implementations MUST take the following precautions:

-  Restrict metadata and JWKS fetches to the "https" scheme.
   Plaintext "http" MUST NOT be used in production.

-  Apply timeouts to all outbound requests during discovery to
   prevent slowloris-style denial of service.

-  Consider maintaining an allowlist of trusted issuer domains
   or URI prefixes.  Tokens with issuers outside the allowlist
   SHOULD be rejected before any network request is made.

-  Validate that "jwks_uri" values in metadata responses are
   HTTPS and belong to the expected issuer's domain.

-  Limit the number of distinct issuers resolved per
   verification to bound network amplification.

When the deployment environment is known, implementations SHOULD
prefer the "resolveKey" callback (or equivalent) over automatic
discovery, providing keys from a trusted local source.

### 10.8.  Hash Binding Security

The "ft_parent" header contains a SHA-256 hash binding each token
to its parent.  SHA-256 is collision-resistant; an attacker cannot
substitute a different parent token without detection.  The hash
is computed over the full compact serialization of the parent token,
including its signature.

## 11.  Normative References

-  **RFC 2119**  Key words for use in RFCs to Indicate Requirement Levels
-  **RFC 7515**  JSON Web Signature (JWS)
-  **RFC 7517**  JSON Web Key (JWK)
-  **RFC 7519**  JSON Web Token (JWT)
-  **draft-ietf-oauth-client-id-metadata-document**  OAuth 2.0 Client ID Metadata Document
-  **RFC 7638**  JSON Web Key (JWK) Thumbprint
-  **RFC 7800**  Proof-of-Possession Key Semantics for JWTs
-  **RFC 8414**  OAuth 2.0 Authorization Server Metadata
-  **RFC 9396**  OAuth 2.0 Rich Authorization Requests
-  **RFC 9449**  OAuth 2.0 Demonstrating Proof of Possession (DPoP)

## 12.  Acknowledgements

The authors would like to thank Bobby Tiernay for his contributions
and feedback during the development of this specification.
