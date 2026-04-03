# French Toast JWT (FT-JWT)

## Token Attenuation through Re-Signing and Claim Layering

### Status of This Document

This document describes the French Toast JWT (FT-JWT) token format and
processing rules for JWT-based token attenuation with proof of possession.

### Abstract

This specification defines a mechanism for attenuating JSON Web Tokens
(JWTs) by re-signing them with additional claims while preserving a
verifiable chain back to the original issuer.  Each token in the chain
embeds its parent in the JOSE header, creating a linked structure that
can be walked during verification.  Tokens are bound to their presenter
via Demonstrating Proof of Possession (DPoP) per RFC 9449.

The mechanism is claim-agnostic: it imposes no semantics on the claims
carried by each token.  Interpretation of claims (scopes, authorization
details, resource restrictions) is left to the verifier.

### Table of Contents

1. Introduction
2. Terminology
3. Token Format
4. Token Issuance
5. Proof of Possession
6. Chain Verification
7. Key Discovery
8. HTTP Usage
9. Security Considerations
10. Normative References

---

## 1.  Introduction

OAuth 2.0 defines a model where an Authorization Server issues access
tokens to clients.  However, there is no standard mechanism for a
client to delegate a subset of its authority to another client -- a
sub-client, a downstream service, or a partner acting on its behalf.

Today, this is typically handled by forwarding the original access
token as-is, granting the downstream party the full authority of the
original client.  Alternatively, the downstream party obtains its own
token through a separate authorization grant, which requires
out-of-band coordination and does not preserve the delegation chain.

FT-JWT addresses this gap by enabling client-to-client, and 
resource-to-resource delegation. A bearer re-signs its access token 
with its own key, adding claims that layer additional context or 
constraints, while embedding the parent token in the JOSE protected header.  
The result is a chain of JWTs that can be verified back to the original 
issuer, with each hop's identity and claims preserved.

Each token in the chain is DPoP-bound, ensuring that only the intended
presenter can use it.  Key discovery leverages existing metadata
documents (Authorization Server Metadata, Client ID Metadata
Documents, and Protected Resource Metadata), requiring no additional
infrastructure.

### 1.1.  Design Goals

-  Claim-agnostic: the library does not interpret claim semantics.
-  Standard JWT format: each token is a valid JWT processable by any
   conformant JWT library.
-  Verifiable chain: the full provenance of a token is recoverable.
-  Proof of possession: tokens cannot be replayed by unauthorized
   parties.
-  Automatic key discovery: keys are resolved via metadata documents
   rather than manual configuration.

## 2.  Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

**FT-JWT**
:  A JWT whose JOSE header contains the "ft_parent" parameter and
   whose "typ" header parameter is "ft+jwt".

**Parent Token**
:  The JWT embedded in the "ft_parent" header parameter.  This is the
   token that was attenuated to produce the current FT-JWT.

**Root Token**
:  The original JWT issued by the Authorization Server.  It has no
   "ft_parent" header parameter.

**Chain**
:  The ordered sequence of tokens from the outermost FT-JWT to the
   root token, linked via "ft_parent" headers.

**Presenter**
:  The entity that presents a token to a downstream service.  The
   token's "cnf.jkt" claim identifies the presenter's key.

## 3.  Token Format

### 3.1.  JOSE Header

An FT-JWT MUST include the following header parameters:

```json
{
  "alg": "ES256",
  "typ": "ft+jwt",
  "ft_parent": "<compact serialization of the parent JWT>"
}
```

**alg**
:  The algorithm used to sign this token.  Any algorithm supported by
   JWS (RFC 7515) MAY be used.

**typ**
:  MUST be "ft+jwt" for French Toast tokens.

**ft_parent**
:  MUST contain the compact serialization (RFC 7519 Section 7.1) of
   the parent JWT.  This is the full, signed parent token string.

### 3.2.  Payload

The payload is a standard JWT Claims Set (RFC 7519 Section 4) with the
following requirements:

```json
{
  "iss": "https://client2.example.com",
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
:  The issuer of this token.  MUST be a URI that resolves to a
   metadata document containing a "jwks_uri" or "jwks" parameter.

**sub** (REQUIRED)
:  The subject.  MUST match the "sub" claim of the parent token.

**aud** (REQUIRED)
:  The intended audience of this token.

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

2.  "exp" MUST NOT exceed the parent token's "exp".

3.  "iat" MUST NOT be before the parent token's "iat".

4.  "iat" MUST be less than or equal to "exp".

5.  "iat" MUST NOT be in the future (subject to clock tolerance).

6.  "exp" MUST NOT be in the past (subject to clock tolerance).

7.  "ft_parent" MUST contain a valid, signed JWT.

8.  Extra claims are opaque to the specification.  The verifier is
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
    c.  Set "aud" to the intended recipient.
    d.  Set "iat" to the current time.
    e.  Set "exp" to the desired expiration, capped to the parent
        token's "exp".
    f.  Set "cnf.jkt" to the JWK Thumbprint of the presenter's
        public key.
    g.  Include any additional claims.

3.  Construct the JOSE header:
    a.  Set "alg" to the signing algorithm.
    b.  Set "typ" to "ft+jwt".
    c.  Set "ft_parent" to the compact serialization of the parent
        token.

4.  Sign the token with the issuer's private key.

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

Refer to RFC 9449 for DPoP proof creation and verification procedures.

## 6.  Chain Verification

### 6.1.  Verification Procedure

To verify an FT-JWT, the verifier MUST perform the following steps:

1.  If a DPoP proof is present, verify it per RFC 9449.

2.  Decode the outermost token's JOSE header.

3.  Verify the outermost token's signature using the issuer's
    public key, discovered per Section 7.

4.  Set depth = 0.  Initialize the chain.

5.  Record the token's header and payload in the chain at the
    current depth.

6.  If the JOSE header contains "ft_parent" and "typ" is "ft+jwt":
    a.  Extract the parent token from "ft_parent".
    b.  Verify the parent token's signature using the parent
        issuer's public key, discovered per Section 7.
    c.  Confirm that the child token's "exp" does not exceed the
        parent token's "exp".
    d.  Confirm that the child token's "iat" is not before the
        parent token's "iat".
    e.  Confirm that the child token's "sub" matches the parent
        token's "sub".
    f.  Confirm that "iat" <= "exp" for the current token.
    g.  Confirm that "iat" is not in the future and "exp" is not
        in the past (subject to clock tolerance).
    h.  Increment depth.  Record the parent in the chain.
    i.  Repeat from step 6 with the parent token.

7.  If no "ft_parent" is present, the current token is the root.
    Verify it against the Authorization Server's published keys.

8.  Return the chain.

### 6.2.  Verification Output

Upon successful verification, the verifier has an ordered list of
decoded tokens from the outermost FT-JWT (depth 0) to the root
token (maximum depth).  For example, a 3-hop chain yields:

    Depth 0:  iss=client2  (outermost FT-JWT)
    Depth 1:  iss=client1
    Depth 2:  iss=AS        (root token)

The verifier is responsible for interpreting the claims at each depth
and enforcing its own authorization policy.

## 7.  Key Discovery

Keys for each issuer in the chain are discovered automatically via
metadata documents.  No manual key configuration is required.

Each participant in the chain MUST publish one of the following
metadata documents at a well-known endpoint:

-  **Authorization Server Metadata** (RFC 8414) at
   "/.well-known/oauth-authorization-server"

-  **Client ID Metadata Document** (draft-ietf-oauth-client-id-metadata-document)

-  **Protected Resource Metadata** (RFC 9728) at
   "/.well-known/oauth-protected-resource".

The metadata document MUST contain a "jwks_uri" parameter pointing to
a JWK Set (RFC 7517), or an inline "jwks" parameter. Note, that the Resource, 
and Client may be colocated.

### 7.1.  Discovery Procedure

For each issuer in the chain, the verifier:

1.  Extracts the "iss" claim from the token.

2.  Attempts to fetch metadata from the following endpoints using #7. 

3.  Parses the "jwks_uri" from the metadata response.

4.  Fetches the JWK Set from the "jwks_uri".

5.  Verifies the token's signature against the keys in the JWK Set.

Implementations SHOULD cache JWK Sets per issuer to avoid redundant
network requests.

## 8.  HTTP Usage

### 8.1.  Sending an FT-JWT

When sending an FT-JWT in an HTTP request, the sender MUST:

1.  Include the token in the Authorization header using the DPoP
    scheme:

    ```
    Authorization: DPoP <ft-jwt>
    ```

2.  Include a DPoP proof in the DPoP header:

    ```
    DPoP: <dpop-proof-jwt>
    ```

### 8.2.  Example: Client1 to Client2

```http
POST /process HTTP/1.1
Host: client2.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6ImZ0K2p3dCIsImZ0X3BhcmVudCI6Ii4uLiJ9...
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7fX0...
Content-Type: application/json

{"task": "analyze-users"}
```

The recipient decodes the access token:

**Header:**
```json
{
  "alg": "ES256",
  "typ": "ft+jwt",
  "ft_parent": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9..."
}
```

**Payload:**
```json
{
  "iss": "https://client1.example.com",
  "sub": "user|abc123",
  "aud": "https://client2.example.com",
  "scope": "read write",
  "cnf": { "jkt": "thumbprint-of-client1-key" }
}
```

The recipient verifies:
1.  The DPoP proof (sender holds the key matching "cnf.jkt").
2.  The token signature (Client1's key, via metadata discovery).
3.  The parent token in "ft_parent" (Authorization Server's key).
4.  Subject consistency throughout the chain.

### 8.3.  Example: Client2 to Resource Server

```http
GET /users HTTP/1.1
Host: rs.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6ImZ0K2p3dCIsImZ0X3BhcmVudCI6Ii4uLiJ9...
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7fX0...
```

**Payload:**
```json
{
  "iss": "https://client2.example.com",
  "sub": "user|abc123",
  "aud": "https://rs.example.com",
  "scope": "read",
  "authorization_details": [
    { "type": "api_endpoint", "actions": ["read"], "locations": ["/users"] }
  ],
  "cnf": { "jkt": "thumbprint-of-client2-key" }
}
```

### 8.4.  Full Chain Walk

```
Token C  (depth 0, iss: client2, scope: read, authorization_details: [...])
  └─ header.ft_parent
       Token B  (depth 1, iss: client1, scope: read write)
         └─ header.ft_parent
              Token A  (depth 2, iss: AS, scope: read write delete)  ← root
```

## 9.  Security Considerations

### 9.1.  Token Replay

DPoP binding mitigates token replay.  Each token's "cnf.jkt" claim
binds it to a specific presenter, and the DPoP proof demonstrates
possession of the corresponding private key at the time of the
request.

### 9.2.  Scope Escalation

This specification does not enforce scope reduction.  It is the
responsibility of the verifier to inspect the claims at each level
of the chain and enforce that privileges are not escalated.
Implementations SHOULD compare claims across the chain and reject
tokens where a child claims broader access than its parent.

### 9.3.  Chain Depth

Implementations SHOULD impose a maximum chain depth to prevent
denial-of-service via deeply nested tokens.  A depth limit of 10
is RECOMMENDED.

### 9.4.  Token Size

Because "ft_parent" embeds the full parent JWT in the header, token
size grows with each hop.  Implementations SHOULD be aware of HTTP
header size limits and consider the practical implications of deep
chains.

### 9.5.  Key Material

Private keys used for signing MUST NOT be extractable.  The DPoP
proof requires only the public key in its header; implementations
MUST accept the public key as a separate parameter rather than
deriving it from the private key.

### 9.6.  Clock Skew

When verifying "exp" constraints across the chain, implementations
SHOULD allow for reasonable clock skew between participants.

## 10.  Normative References

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
-  **RFC 9728**  OAuth 2.0 Protected Resource Metadata
