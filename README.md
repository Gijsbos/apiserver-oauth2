# API Server OAuth2

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.4-blue.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/gijsbos/apiserver-oauth2/ci.yml?branch=main)](https://github.com/gijsbos/apiserver-oauth2/actions)
[![Issues](https://img.shields.io/github/issues/gijsbos/apiserver-oauth2)](https://github.com/gijsbos/apiserver-oauth2/issues)
[![Last Commit](https://img.shields.io/github/last-commit/gijsbos/apiserver-oauth2)](https://github.com/gijsbos/apiserver-oauth2/commits/main)

---

## Introduction

OAuth2 / JWT access-token verification for [`gijsbos/apiserver`](https://github.com/gijsbos/apiserver).

Verifies Bearer tokens as JWTs (RFC 7519) against a JSON Web Key Set — supplied directly, fetched from a
URL, or discovered via OpenID Connect (`.well-known/openid-configuration`) — and provides `#[HasScope]` /
`#[HasRole]` route attributes for scope- and role-gated authorization, built on apiserver's generic
`#[RequiresAuthority]` mechanism.

apiserver itself stays OAuth2-ignorant: `SecurityContext` only decides whether a path needs *some*
credential, and `RequiresAuthority` only knows how to run a pluggable `RouteAuthorityVerifierInterface`. This
package supplies the OAuth2-specific pieces on top of that: token verification, key resolution, and two
ready-made checks (`HasScope`, `HasRole`).

---

## Requirements

- **PHP**: `>= 8.4`
- **gijsbos/apiserver**: `^1.13`
- **gijsbos/http**: `^1.2`
- **web-token/jwt-framework**: `^4.2`
- **psr/clock**: `^1.0`
- **ext-apcu** *(optional, recommended)* — used automatically to cache fetched JWKS keys across requests when available

## Installation

```
composer require gijsbos/apiserver-oauth2
```

## Setup

### 1. Define a verification policy

```php
use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;

$policy = new OAuth2VerificationPolicy(
    issuerUri: "https://issuer.example.com",     // used for OIDC discovery and to validate the "iss" claim
    keysUri: "https://issuer.example.com/keys",  // or supply "keys" directly, or omit and rely on issuerUri alone
    audience: "your-api-audience",               // optional - validates the "aud" claim
    kidRequired: true,                           // optional - require a "kid" in the token header
);
```

At least one of `keys`, `keysUri`, or `issuerUri` must be set (checked when keys are first needed), and `allowedAlgorithms` (default: RS256) must
not be empty. See the class docblock for the full precedence order between the key sources
(`keys` > `keysUri` > `issuerUri`) and what each one does to `iss` validation.

Keys fetched from `keysUri` / `issuerUri` are cached in process memory and in APCu (when available). The
defaults can be changed through static properties of `CertificateProvider`:

| Property | Default | Meaning |
| --- | --- | --- |
| `$CACHE_TTL_SECONDS` | `3600` | How long fetched keys are cached. |
| `$REFRESH_COOLDOWN_SECONDS` | `60` | A token whose `kid` is not in the cached keys (e.g. after a key rotation) triggers a refetch, at most once per this period. |
| `$FAILURE_CACHE_TTL_SECONDS` | `30` | How long a failed fetch is remembered, so an unreachable issuer does not slow down every request. |
| `$HTTP_TIMEOUT_SECONDS` / `$HTTP_CONNECT_TIMEOUT_SECONDS` | `5` / `3` | Timeouts of a single fetch. |

With OpenID Connect discovery, the configuration document's `issuer` must match `issuerUri` (a trailing slash
aside), otherwise the keys are not used.

### 2. Use `OAuth2Server` instead of `Server` in your entrypoint

```php
use gijsbos\ApiServer\OAuth2\OAuth2Server;

$server = new OAuth2Server($policy, [
    // same options as gijsbos\ApiServer\Server
]);

$server->listen();
```

`OAuth2Server` takes the policy as its first argument and wires `AuthorizationHeaderVerifier::$viaBearer` from it,
so any `#[RequiresAuthority]`-based check — including `SecurityContext`-gated paths and `HasScope` /
`HasRole` — can verify Bearer tokens with no further setup. Only the Bearer scheme is supported; `Basic`
credentials are rejected with `schemeNotSupported`.

### 3. Gate paths broadly with `SecurityContext`

`SecurityContext` lives in `gijsbos/apiserver`, not this package, but it's how you decide which paths
need a token at all before anything OAuth2-specific runs:

```php
use gijsbos\ApiServer\Server;
use gijsbos\ApiServer\SecurityContext;

Server::$securityContext = new SecurityContext()
    ->permitAll("/health", "/.well-known/**")
    ->requireAuth("/api/**");
```

### 4. Gate individual routes by scope or role

```php
class UserController extends RouteController
{
    #[GetRoute('/user/{id}/')]
    #[HasScope('user:read')]
    public function getUser(/* ... */) { /* ... */ }

    #[DeleteRoute('/user/{id}/')]
    #[HasScope('user:delete,admin:all')] // comma-separated - any one match is enough
    public function deleteUser(/* ... */) { /* ... */ }

    #[PostRoute('/admin/settings')]
    #[HasRole('admin')]
    public function updateSettings(/* ... */) { /* ... */ }
}
```

`HasScope` checks the token's `scp` / `scopes` / `scope` claim and `HasRole` checks `roles` / `role`. In both
cases the first claim present wins (there is no fallback to a later one), and the claim may be either a
delimited string (space, or comma) or a JSON array of strings. A claim of any other type, or an array holding
anything but strings, is treated as malformed and denied. Matching is exact: case-sensitive, no prefixes.

Both attributes accept a comma-separated string or an array; multiple values are OR'd together. Empty
entries are ignored, so an attribute without any usable value can never be satisfied and always denies. When
a route carries both `#[HasScope]` and `#[HasRole]`, both must pass.

Denials are `403` responses with these error codes:

| Attribute | Error code |
| --- | --- |
| `HasScope` | `insufficientScope` — the camelCase form of RFC 6750 §3.1's `insufficient_scope` (all error codes in this package are camelCase) |
| `HasRole` | `insufficientRole` — roles aren't part of the OAuth2 spec, so there's no RFC code for that case |

Token problems are `401` responses: `authorizationRequired`, `authorizationHeaderInvalid`, `schemeNotSupported`,
`tokenInvalid`, `tokenHeaderInvalid`, `tokenKeyNotFound`, `tokenKeyInvalid`, `tokenPayloadInvalid`,
`tokenKeysUnavailable` and `tokenIssuerUnavailable`.

### Custom authority checks

For anything beyond scope/role, implement `RouteAuthorityVerifierInterface` yourself and use apiserver's
`#[RequiresAuthority]` directly:

```php
use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Attributes\RequiresAuthority;
use gijsbos\ApiServer\Interfaces\RouteAuthorityVerifierInterface;

class IsAccountOwnerCheck implements RouteAuthorityVerifierInterface
{
    public function execute(Route $route, array $authority)
    {
        // Inspect $route->getData() (or look anything else up yourself),
        // throw to deny, return normally to allow. $authority is whatever
        // was passed as the attribute's second argument.
    }
}

#[RequiresAuthority(IsAccountOwnerCheck::class, [])]
```

`HasScope` and `HasRole` are themselves just `RequiresAuthority` subclasses that supply `ScopeVerifier` /
`RoleVerifier` as the check — following the same pattern is the intended way to extend authorization
beyond what this package ships.

## Components

| Class | Purpose |
| --- | --- |
| `OAuth2Server` | Extends `Server`; wires OAuth2 bearer-token verification from a registered policy. |
| `OAuth2VerificationPolicy` | Configures issuer, key source, audience, allowed algorithms, `kid` requirement. |
| `AccessTokenVerifier` | Verifies a JWT's header, signature, and standard claims (`exp`, `nbf`, `iss`, `aud`) against a policy. Returns a `TokenPayload`. |
| `CertificateProvider` | Provides the policy's keys directly, or fetches them from a JWKS URL or via OpenID Connect discovery; caches in APCu when available. |
| `SystemClock` | Default PSR-20 clock for `exp`/`nbf` checks. `AccessTokenVerifier` accepts any `Psr\Clock\ClockInterface`, e.g. a frozen clock in tests. |
| `HasScope` / `ScopeVerifier` | Route attribute + backing check for scope-gated authorization. |
| `HasRole` / `RoleVerifier` | Route attribute + backing check for role-gated authorization. |

## Testing

```
vendor/bin/phpunit
```

The route tests send real HTTP requests to `index.php`, so the package must be served (e.g. by MAMP/Apache) and
`BASE_URL` in `.env` must point at it, e.g. `BASE_URL=http://localhost/apiserver-oauth2`.

## Contributions

Contributions are welcome!
Please open an issue or submit a pull request following our contribution guidelines.
