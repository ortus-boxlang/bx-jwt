# BoxLang JWT Module 🔐

A production-ready BoxLang module for creating, signing, verifying, encrypting, and decrypting JSON Web Tokens (JWT/JWE).

```
╔═══════════════════════════════════════════════════════╗
║            ⚡ B o x L a n g  J W T                    ║
║       Secure · Standards-Based · Production-Ready     ║
╚═══════════════════════════════════════════════════════╝
```

<blockquote>
	Copyright Since 2026 by Ortus Solutions, Corp<br>
	<a href="https://www.boxlang.io">www.boxlang.io</a> |
	<a href="https://www.ortussolutions.com">www.ortussolutions.com</a>
</blockquote>

---

## Available BIFs

| BIF | Signature | Description |
| --- | --------- | ----------- |
| `jwtNew` | `jwtNew()` | Returns a fluent `JwtBuilder` for chainable token construction. Terminate with `.sign()` or `.encrypt()`. |
| `jwtCreate` | `jwtCreate( payload, [key], [algorithm], [options] )` | Signs a payload struct and returns a compact JWS token string. |
| `jwtVerify` | `jwtVerify( token, [key], [algorithm], [options] )` | Verifies a JWS signature and validates claims. Returns the claims struct. Throws on any failure. |
| `jwtValidate` | `jwtValidate( token, [key], [algorithm], [options] )` | Like `jwtVerify` but returns `true`/`false` instead of throwing. |
| `jwtDecode` | `jwtDecode( token )` | Decodes a JWS token **without** verifying the signature. Returns `{ header: {}, payload: {} }`. |
| `jwtRefresh` | `jwtRefresh( token, [key], [algorithm], [options] )` | Re-issues a token with fresh `iat`, `jti`, and optionally a new `exp`. All application claims are preserved. |
| `jwtEncrypt` | `jwtEncrypt( payload, [key], [options] )` | Encrypts a payload as a compact JWE token string. |
| `jwtDecrypt` | `jwtDecrypt( token, [key], [options] )` | Decrypts a JWE token and returns the claims struct. |
| `jwtGenerateSecret` | `jwtGenerateSecret( [bits] )` | Generates a cryptographically random Base64-encoded HMAC secret. Default: 256 bits. |
| `jwtGenerateKeyPair` | `jwtGenerateKeyPair( [algorithm] )` | Generates an RSA or EC key pair and returns `{ privateKey: "...", publicKey: "..." }` as PEM strings. |

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Fluent Builder API](#fluent-builder-api)
- [BIF Reference](#bif-reference)
- [Module Configuration](#module-configuration)
- [Key Registry](#key-registry)
- [Algorithm Support](#algorithm-support)
- [Security](#security)
- [Examples](#examples)
- [License](#license)

---

## Overview

**bx-jwt** is a comprehensive JWT/JWE library for BoxLang, it fully implements:

- **JWS** (JSON Web Signature) — signed tokens using HMAC, RSA, or EC keys
- **JWE** (JSON Web Encryption) — encrypted tokens using RSA or symmetric keys
- **RFC 7518** — JSON Web Algorithms
- **RFC 7519** — JSON Web Token

### Two Ways to Work with JWTs

| API | Entry Point | Best For |
|-----|-------------|----------|
| **Fluent Builder** ✨ | `jwtNew()` | Readable, chainable token construction |
| **BIF Functions** 📚 | `jwtCreate()`, `jwtVerify()`, etc. | Direct, functional style |

---

## Features

- 🔑 **HMAC Signing** — HS256, HS384, HS512 with RFC 7518 minimum key length enforcement
- 🔐 **RSA Signing** — RS256, RS384, RS512
- 📐 **EC Signing** — ES256 (P-256), ES384 (P-384), ES512 (P-521)
- 🔒 **JWE Encryption** — RSA-OAEP-256, direct symmetric (`dir`) with A256GCM
- 🗝️ **Named Key Registry** — register keys by name in module config; reference by name in BIFs
- 🏗️ **Fluent Builder** — `jwtNew()` returns a chainable builder for elegant token creation
- ♻️ **Token Refresh** — `jwtRefresh()` re-issues a token with fresh time claims
- 🔓 **Decode Without Verify** — `jwtDecode()` inspects headers/claims before choosing a key
- ✅ **Boolean Validation** — `jwtValidate()` returns true/false without throwing exceptions
- 🔧 **Key Generation** — `jwtGenerateSecret()` and `jwtGenerateKeyPair()` for easy key creation
- ⏱️ **Clock Skew** — configurable tolerance for `exp` and `nbf` validation
- 📋 **Default Claims** — auto-inject `iss`, `aud`, `exp`, `iat`, `jti` from module settings
- 🚫 **`alg:none` Protection** — unconditionally rejects unsigned tokens
- 📋 **Algorithm Allowlist** — restrict permitted algorithms via module settings

---

## Requirements

- **BoxLang Runtime** 1.0.0 or higher
- **BoxLang+ License** — This module requires a BoxLang+ license

---

## Installation

```bash
box install bx-jwt
```

---

## Quick Start

### Sign and Verify (HMAC)

```javascript
secret  = jwtGenerateSecret( 256 );   // cryptographically random 256-bit secret
token   = jwtCreate( { sub: "user-123", iss: "my-api", roles: [ "admin" ] }, secret, "HS256" );
payload = jwtVerify( token, secret, "HS256" );
writeOutput( payload.sub );  // user-123
```

### Sign and Verify (RSA)

```javascript
keys    = jwtGenerateKeyPair( "RS256" );
token   = jwtCreate( { sub: "user-123" }, keys.privateKey, "RS256" );
payload = jwtVerify( token, keys.publicKey, "RS256" );
```

### Fluent Builder

```javascript
token = jwtNew()
    .subject( "user-123" )
    .issuer( "my-api" )
    .audience( "mobile-client" )
    .claim( "roles", [ "admin", "user" ] )
    .expireIn( 3600 )
    .header( "kid", "v1" )
    .sign( secret, "HS256" );
```

### Encrypt and Decrypt (JWE)

```javascript
token   = jwtEncrypt( { sub: "user-123", ssn: "123-45-6789" }, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
payload = jwtDecrypt( token, secret, { keyAlgorithm: "dir", encAlgorithm: "A256GCM" } );
```

---

## Fluent Builder API

`jwtNew()` returns a `JwtBuilder` object. Chain methods, then terminate with `.sign()` or `.encrypt()`.

### Claim Methods

| Method | Description |
|--------|-------------|
| `subject( val )` | Sets the `sub` claim |
| `issuer( val )` | Sets the `iss` claim |
| `audience( val )` | Sets the `aud` claim — accepts a string or array |
| `claim( key, val )` | Sets any custom claim |
| `withPayload( struct )` | Replaces the entire payload with the given struct |
| `expireIn( seconds )` | Sets `exp` as now + seconds |
| `expireAt( date )` | Sets `exp` to an explicit DateTime |
| `issuedNow()` | Sets `iat` to now |
| `issuedAt( date )` | Sets `iat` to an explicit DateTime |
| `notBefore( date )` | Sets the `nbf` claim |
| `jti( val )` | Sets the `jti` (JWT ID) claim |

### Header Methods

| Method | Description |
|--------|-------------|
| `header( key, val )` | Sets a JOSE header field (e.g., `kid`, `typ`, `cty`) |

### Terminal Methods

| Method | Description |
|--------|-------------|
| `sign( [key], [algorithm] )` | Signs and returns the compact JWT string |
| `encrypt( [key], [keyAlgorithm], [encAlgorithm] )` | Encrypts and returns the compact JWE string |

### Builder Examples

```javascript
// HMAC with custom headers
token = jwtNew()
    .subject( "alice" )
    .claim( "tenant", "acme-corp" )
    .expireIn( 900 )
    .header( "kid", "signing-key-v2" )
    .sign( secret, "HS256" );

// RSA with all standard claims
token = jwtNew()
    .subject( "svc-account" )
    .issuer( "auth-service" )
    .audience( [ "api", "analytics" ] )
    .issuedNow()
    .expireIn( 3600 )
    .jti( createUUID() )
    .sign( privateKeyPem, "RS256" );

// JWE encryption
token = jwtNew()
    .subject( "patient-456" )
    .claim( "phi", { dob: "1990-01-15", ssn: "xxx-xx-1234" } )
    .encrypt( secret, "dir", "A256GCM" );

// Use withPayload for existing structs
payload = { sub: "user-1", iss: "my-api", roles: [ "admin" ] };
token   = jwtNew().withPayload( payload ).expireIn( 3600 ).sign( secret, "HS256" );
```

---

## BIF Reference

### `jwtCreate( payload, [key], [algorithm], [options] )`

Creates a signed JWT (JWS).

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `payload` | Struct | Yes | Claims to encode |
| `key` | Any | No | Signing key — named key, HMAC secret, or PEM/JWK string. Optional when `defaultSigningKey` is configured. |
| `algorithm` | String | No | Signing algorithm. Optional when resolved from key metadata or `defaultAlgorithm`. |
| `options` | Struct | No | `headers` (struct of custom JOSE headers), `generateIat`, `generateJti` |

```javascript
// HMAC
token = jwtCreate( { sub: "u1", iss: "api" }, "my-32-byte-secret-goes-here!!!", "HS256" );

// RSA with custom header
token = jwtCreate( { sub: "u1" }, privateKeyPem, "RS256", { headers: { kid: "rsa-v1" } } );

// Named key from registry
token = jwtCreate( { sub: "u1" }, "myapp-hmac" );

// Disable auto-generated iat for this call
token = jwtCreate( { sub: "u1", iat: specificDate }, secret, "HS256", { generateIat: false } );
```

---

### `jwtVerify( token, [key], [algorithm], [options] )`

Verifies a JWT signature and validates claims. Returns the claims struct. Throws on failure.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `token` | String | Yes | Compact JWT string |
| `key` | Any | No | Verification key. Optional when `defaultVerifyKey` / `defaultSigningKey` is configured. |
| `algorithm` | String | No | Expected algorithm |
| `options` | Struct | No | `claims` (struct of expected claim values), `clockSkew` (seconds) |

**Throws:**

- `bxjwt.JWTVerificationException` — bad signature or claim mismatch
- `bxjwt.JWTExpiredException` — token is expired
- `bxjwt.JWTNotYetValidException` — token not yet valid (`nbf`)
- `bxjwt.JWTParseException` — malformed token

```javascript
// Basic verify
payload = jwtVerify( token, secret, "HS256" );

// With claim assertions
payload = jwtVerify( token, secret, "HS256", {
    claims: { iss: "my-api", aud: "mobile-app" }
} );

// With explicit clock skew
payload = jwtVerify( token, secret, "HS256", { clockSkew: 30 } );

// RSA
payload = jwtVerify( token, publicKeyPem, "RS256" );
```

---

### `jwtValidate( token, [key], [algorithm], [options] )`

Like `jwtVerify()` but returns `true`/`false` instead of throwing. Useful for simple conditional checks.

```javascript
if ( jwtValidate( token, secret, "HS256" ) ) {
    payload = jwtVerify( token, secret, "HS256" );
    // proceed
} else {
    // redirect to login
}
```

---

### `jwtDecode( token )`

Decodes a signed JWT **without verifying the signature**. Returns a struct with `header` and `payload` keys. Use this to inspect the `kid` or `alg` header before deciding which key to use for verification.

```javascript
decoded = jwtDecode( token );
kid     = decoded.header.kid;     // e.g., "v2"
alg     = decoded.header.alg;     // e.g., "RS256"
sub     = decoded.payload.sub;    // claims are readable without verification

// Typical key-dispatch pattern
decoded = jwtDecode( token );
key     = getKeyById( decoded.header.kid );
payload = jwtVerify( token, key, decoded.header.alg );
```

---

### `jwtRefresh( token, [key], [algorithm], [options] )`

Verifies an existing JWT and re-issues it with fresh `iat`, `jti`, and optionally a new `exp`. All application claims (`sub`, `iss`, `aud`, custom claims) are preserved.

| Option | Type | Description |
|--------|------|-------------|
| `allowExpired` | Boolean | Allow refreshing an expired token (signature is still verified). Default: `false`. |
| `expireIn` | Numeric | Seconds until the refreshed token expires. |
| `headers` | Struct | JOSE headers to include in the new token (overrides the originals). |

```javascript
// Standard refresh — token must still be valid
newToken = jwtRefresh( oldToken, secret, "HS256" );

// Refresh with a new 1-hour expiration
newToken = jwtRefresh( oldToken, secret, "HS256", { expireIn: 3600 } );

// Allow refreshing even if the token just expired (grace period)
newToken = jwtRefresh( oldToken, secret, "HS256", {
    allowExpired: true,
    expireIn: 3600
} );
```

---

### `jwtEncrypt( payload, [key], [options] )`

Encrypts a payload as a JWE (JSON Web Encryption). The payload can be a struct or any value.

| Option | Type | Description |
|--------|------|-------------|
| `keyAlgorithm` | String | Key management algorithm. Default: `RSA-OAEP-256`. |
| `encAlgorithm` | String | Content encryption algorithm. Default: `A256GCM`. |
| `headers` | Struct | Custom JOSE headers. |

```javascript
// RSA key wrapping (asymmetric encryption)
token = jwtEncrypt( { sub: "u1", ssn: "123-45-6789" }, rsaPublicKeyPem, {
    keyAlgorithm: "RSA-OAEP-256",
    encAlgorithm: "A256GCM"
} );

// Direct symmetric encryption (32-byte key for A256GCM)
token = jwtEncrypt( { sub: "u1" }, secret32bytes, {
    keyAlgorithm: "dir",
    encAlgorithm: "A256GCM"
} );
```

---

### `jwtDecrypt( token, [key], [options] )`

Decrypts a JWE token. Returns the decrypted claims as a struct.

```javascript
payload = jwtDecrypt( token, rsaPrivateKeyPem, {
    keyAlgorithm: "RSA-OAEP-256",
    encAlgorithm: "A256GCM"
} );

payload = jwtDecrypt( token, secret32bytes, {
    keyAlgorithm: "dir",
    encAlgorithm: "A256GCM"
} );
```

---

### `jwtNew()`

Returns a new `JwtBuilder` instance. See [Fluent Builder API](#-fluent-builder-api).

---

### `jwtGenerateSecret( [bits] )`

Generates a cryptographically random HMAC secret and returns it as a Base64-encoded string.

| Argument | Default | Description |
|----------|---------|-------------|
| `bits` | `256` | Key length in bits. Must be ≥ 128 and a multiple of 8. |

```javascript
secret256 = jwtGenerateSecret();       // 256-bit for HS256
secret384 = jwtGenerateSecret( 384 );  // 384-bit for HS384
secret512 = jwtGenerateSecret( 512 );  // 512-bit for HS512
```

---

### `jwtGenerateKeyPair( [algorithm] )`

Generates an asymmetric key pair and returns a struct with `privateKey` and `publicKey` as PEM strings.

| Algorithm | Key Type | Key Size |
|-----------|----------|----------|
| `RS256` / `RS384` | RSA | 2048-bit |
| `RS512` | RSA | 4096-bit |
| `ES256` | EC P-256 | — |
| `ES384` | EC P-384 | — |
| `ES512` | EC P-521 | — |

```javascript
rsaKeys = jwtGenerateKeyPair( "RS256" );
token   = jwtCreate( { sub: "u1" }, rsaKeys.privateKey, "RS256" );
payload = jwtVerify( token, rsaKeys.publicKey, "RS256" );

ecKeys  = jwtGenerateKeyPair( "ES256" );
token   = jwtCreate( { sub: "u1" }, ecKeys.privateKey, "ES256" );
payload = jwtVerify( token, ecKeys.publicKey, "ES256" );
```

---

## Module Configuration

Configure defaults and the key registry in `ModuleConfig.bx` or your application's BoxLang configuration.

```javascript
settings = {

    // -----------------------------------------------------------------------
    // Key Registry
    // -----------------------------------------------------------------------
    // Named keys referenced by name in all BIF calls (e.g., jwtCreate({}, "myapp-hmac"))
    keys: {
        // "myapp-hmac": {
        //     algorithm : "HS256",
        //     secret    : "${env.JWT_SECRET}"
        // },
        // "myapp-rsa": {
        //     algorithm  : "RS256",
        //     privateKey : "/path/to/private.pem",
        //     publicKey  : "/path/to/public.pem"
        // }
    },

    // -----------------------------------------------------------------------
    // Signature Defaults
    // -----------------------------------------------------------------------
    defaultSigningKey    : "",    // Named key used when no key argument is provided to jwtCreate/jwtRefresh
    defaultVerifyKey     : "",    // Named key used when no key argument is provided to jwtVerify/jwtValidate
    defaultAlgorithm     : "HS256",

    // -----------------------------------------------------------------------
    // Encryption Defaults
    // -----------------------------------------------------------------------
    defaultEncryptionKey : "",    // Named key for jwtEncrypt
    defaultDecryptionKey : "",    // Named key for jwtDecrypt
    defaultKeyAlgorithm  : "RSA-OAEP-256",
    defaultEncAlgorithm  : "A256GCM",

    // -----------------------------------------------------------------------
    // Token Behavior
    // -----------------------------------------------------------------------
    generateIat          : true,  // Auto-inject "iat" (issued-at) if not in payload
    generateJti          : true,  // Auto-inject "jti" (JWT ID) if not in payload
    clockSkew            : 60,    // Seconds of clock skew tolerance for exp/nbf

    // -----------------------------------------------------------------------
    // Default Claims (auto-injected when not present in the payload)
    // -----------------------------------------------------------------------
    defaultIssuer        : "",    // Auto-inject "iss" claim
    defaultAudience      : "",    // Auto-inject "aud" claim
    defaultExpiration    : 0,     // Seconds from now; 0 disables auto-expiry

    // -----------------------------------------------------------------------
    // Security
    // -----------------------------------------------------------------------
    // When non-empty, only algorithms in this list are accepted for sign/verify.
    allowedAlgorithms    : []     // e.g. [ "HS256", "RS256", "ES256" ]
}
```

---

## Key Registry

The key registry lets you define keys once in configuration and reference them by name throughout your application. This keeps secrets out of application logic and makes key rotation easy.

### Defining Keys

```javascript
// ModuleConfig.bx settings.keys
keys: {

    // HMAC secret — supports ${env.VAR} placeholder substitution
    "api-signing": {
        algorithm : "HS256",
        secret    : "${env.JWT_HMAC_SECRET}"
    },

    // RSA key pair (PEM file paths or inline PEM strings)
    "api-rsa": {
        algorithm  : "RS256",
        privateKey : "/etc/keys/api-private.pem",
        publicKey  : "/etc/keys/api-public.pem"
    },

    // Public-only key for verifying third-party tokens
    "partner-public": {
        algorithm : "RS256",
        publicKey : "/etc/keys/partner-public.pem"
    },

    // JWK (JSON Web Key) defined inline
    "oidc-verify": {
        algorithm : "RS256",
        jwk       : { kty: "RSA", n: "...", e: "AQAB" }
    }
}
```

### Using Named Keys

```javascript
// Use the named key — algorithm is resolved from key metadata automatically
token   = jwtCreate( { sub: "u1" }, "api-signing" );
payload = jwtVerify( token, "api-signing" );

// Set module defaults so the key argument is optional
// (set defaultSigningKey and defaultVerifyKey in config)
token   = jwtCreate( { sub: "u1" } );
payload = jwtVerify( token );
```

### Runtime Key Management

```javascript
jwtService = getBoxContext().getRuntime().getGlobalService( "JWTService" );

// Register a key at runtime
jwtService.registerKey( "session-key", {
    algorithm : "HS256",
    secret    : generateSecureKey()
} );

// Check and remove keys
hasKey = jwtService.hasKey( "session-key" );
names  = jwtService.getKeyNames();
jwtService.removeKey( "session-key" );
```

---

## Algorithm Support

### Signing (JWS)

| Algorithm | Type | Min Key Size | Notes |
|-----------|------|-------------|-------|
| `HS256` | HMAC | 256 bits (32 bytes) | Symmetric — same key signs and verifies |
| `HS384` | HMAC | 384 bits (48 bytes) | Symmetric |
| `HS512` | HMAC | 512 bits (64 bytes) | Symmetric |
| `RS256` | RSA | 2048-bit | Asymmetric — private key signs, public key verifies |
| `RS384` | RSA | 2048-bit | Asymmetric |
| `RS512` | RSA | 4096-bit | Asymmetric |
| `ES256` | EC P-256 | — | Asymmetric, smaller keys than RSA |
| `ES384` | EC P-384 | — | Asymmetric |
| `ES512` | EC P-521 | — | Asymmetric |

### Encryption (JWE)

| Key Algorithm | Content Enc. | Key Type |
|---------------|-------------|----------|
| `RSA-OAEP-256` | `A256GCM` | RSA public/private key pair |
| `dir` | `A256GCM` | 256-bit symmetric secret (32 bytes) |

---

## Security

### `alg:none` Protection

`alg:none` is **unconditionally rejected**. Passing an unsigned token to `jwtVerify()` or `jwtRefresh()` always throws `JWTVerificationException`.

### HMAC Minimum Key Lengths (RFC 7518 §3.2)

The module enforces minimum key lengths when parsing HMAC secrets:

| Algorithm | Minimum |
|-----------|---------|
| HS256 | 32 bytes (256 bits) |
| HS384 | 48 bytes (384 bits) |
| HS512 | 64 bytes (512 bits) |

Use `jwtGenerateSecret(bits)` to always produce a compliant key.

### Algorithm Allowlist

Restrict your application to a known set of algorithms to prevent algorithm-confusion attacks:

```javascript
// ModuleConfig.bx
allowedAlgorithms: [ "HS256", "RS256" ]
```

Any token signed with an algorithm not in the list throws `JWTVerificationException`.

### Clock Skew

`clockSkew` (default: 60 seconds) provides tolerance for clock drift between services without creating large vulnerability windows. Tune it per environment:

```javascript
// Strict: no skew tolerance
payload = jwtVerify( token, secret, "HS256", { clockSkew: 0 } );

// Looser: 2-minute window for distributed systems
payload = jwtVerify( token, secret, "HS256", { clockSkew: 120 } );
```

---

## Examples

### Authentication Middleware Pattern

```javascript
// Issue a token at login
function issueToken( userId, roles ) {
    return jwtCreate( {
        sub   : userId,
        roles : roles,
        iss   : "auth-service",
        aud   : "api"
    }, application.jwtSecret, "HS256", {} );
}

// Validate on every protected request
function requireAuth() {
    var authHeader = getHttpRequestData().headers[ "Authorization" ] ?: "";
    if ( !authHeader.startsWith( "Bearer " ) ) {
        httpStatusCode( 401 );
        abort;
    }
    var token = authHeader.removeFirst( "Bearer " );
    if ( !jwtValidate( token, application.jwtSecret, "HS256" ) ) {
        httpStatusCode( 401 );
        abort;
    }
    request.currentUser = jwtVerify( token, application.jwtSecret, "HS256", {
        claims: { iss: "auth-service", aud: "api" }
    } );
}
```

### Token Refresh Endpoint

```javascript
function refreshToken() {
    var oldToken = arguments.token;
    try {
        // Refresh with 1-hour new expiry; allow up to 7 days past expiry
        var newToken = jwtRefresh( oldToken, application.jwtSecret, "HS256", {
            allowExpired : true,
            expireIn     : 3600,
            claims       : { iss: "auth-service" }
        } );
        return { token: newToken };
    } catch ( "bxjwt.JWTVerificationException" e ) {
        // Bad signature — do not refresh
        return { error: "Invalid token" };
    }
}
```

### Kid-Based Key Rotation

```javascript
// Decode first to find the key ID, then verify with the right key
function verifyWithKeyRotation( token ) {
    var decoded = jwtDecode( token );
    var kid     = decoded.header.kid ?: "default";
    var key     = getKeyForKid( kid );   // your lookup function
    return jwtVerify( token, key, decoded.header.alg );
}
```

### Nested JWT (Sign then Encrypt)

```javascript
// Inner signed JWT
signedToken = jwtCreate( { sub: "u1", role: "admin" }, innerPrivKey, "RS256", {
    headers: { cty: "JWT" }
} );

// Outer encrypted JWE wrapping the signed JWT
encryptedToken = jwtEncrypt( signedToken, outerPubKey, {
    keyAlgorithm : "RSA-OAEP-256",
    encAlgorithm : "A256GCM",
    headers      : { cty: "JWT" }
} );

// Decrypt and then verify
decrypted = jwtDecrypt( encryptedToken, outerPrivKey, {
    keyAlgorithm : "RSA-OAEP-256",
    encAlgorithm : "A256GCM"
} );
payload = jwtVerify( decrypted.payload, innerPubKey, "RS256" );
```

### Module-Level Defaults (Zero-Argument BIFs)

When defaults are fully configured, the key and algorithm arguments become optional:

```javascript
// ModuleConfig.bx
settings = {
    keys             : { "app": { algorithm: "HS256", secret: "${env.JWT_SECRET}" } },
    defaultSigningKey: "app",
    defaultVerifyKey : "app",
    defaultAlgorithm : "HS256",
    defaultIssuer    : "my-api",
    defaultAudience  : "web",
    defaultExpiration: 3600,
    generateIat      : true,
    generateJti      : true
}

// Application code — no key or algorithm arguments needed
token   = jwtCreate( { sub: "user-123" } );
payload = jwtVerify( token );
```

### Generating and Storing Keys

```javascript
// Generate and display keys for storage in environment variables or secret manager
hmacSecret = jwtGenerateSecret( 256 );
writeOutput( "JWT_HMAC_SECRET=" & hmacSecret );

rsaKeys = jwtGenerateKeyPair( "RS256" );
fileWrite( "/etc/keys/private.pem", rsaKeys.privateKey );
fileWrite( "/etc/keys/public.pem",  rsaKeys.publicKey  );

ecKeys  = jwtGenerateKeyPair( "ES256" );
writeOutput( ecKeys.privateKey );
writeOutput( ecKeys.publicKey );
```

---

## License

Licensed under the [BoxLang Plus Subscription License](https://www.boxlang.io/license).

---

Built with ❤️ by [Ortus Solutions](https://www.ortussolutions.com)

<blockquote>
	<a href="https://patreon.com/ortussolutions">Become a Patron</a> — BoxLang is community-funded open source.<br>
	Patreon supporters receive cfcasts access, ForgeBox Pro, and more.
</blockquote>

> "I am the way, and the truth, and the life; no one comes to the Father, but by me (JESUS)" Jn 14:1-12
