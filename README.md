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
credential, and `RequiresAuthority` only knows how to run a pluggable `AuthorityCheckInterface`. This
package supplies the OAuth2-specific pieces on top of that: token verification, key resolution, and two
ready-made checks (`HasScope`, `HasRole`).

---

## Requirements

- **PHP**: `>= 8.4`
- **gijsbos/apiserver**: `^1.9`
- **gijsbos/http**: `^1.2`
- **web-token/jwt-framework**: `^4.2`
- **psr/clock**: `^1.0`
- **ext-apcu** *(optional, recommended)* — used automatically to cache fetched JWKS keys across requests when available

## Installation

```
composer require gijsbos/apiserver-oauth2
```

## Setup

### 1. Define a verification policy and register it

```php
use gijsbos\ApiServer\OAuth2\OAuth2Server;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;

OAuth2Server::addAccessTokenVerificationPolicy(new AccessTokenVerificationPolicy(
    issuerUri: "https://issuer.example.com",     // used for OIDC discovery and to validate the "iss" claim
    keysUri: "https://issuer.example.com/keys",  // or supply "keys" directly, or omit and rely on issuerUri alone
    audience: "your-api-audience",               // optional - validates the "aud" claim
    kidRequired: true,                           // optional - require a "kid" in the token header
));
```

At least one of `keys`, `keysUri`, or `issuerUri` must be set. See the class docblock for the full
precedence order between them (`keys` > `keysUri` > `issuerUri`) and what each one does to `iss` validation.

### 2. Use `OAuth2Server` instead of `Server` in your entrypoint

```php
use gijsbos\ApiServer\OAuth2\OAuth2Server;

$server = new OAuth2Server([
    // same options as gijsbos\ApiServer\Server
]);

$server->listen();
```

`OAuth2Server` wires `AuthenticationVerifier::$viaBearer` automatically from the registered policy, so any
`#[RequiresAuthority]`-based check — including `SecurityContext`-gated paths and `HasScope` / `HasRole` —
can verify Bearer tokens with no further setup.

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

`HasScope` checks the token's `scp` / `scopes` / `scope` claim (space- or comma-delimited, per RFC 6749
§3.3) and denies with the standard `insufficient_scope` error (RFC 6750 §3.1). `HasRole` checks `role` /
`roles` (accepts either a JSON array or a delimited string) and denies with `insufficient_role` — roles
aren't part of the OAuth2 spec, so there's no RFC code for that case. Both attributes accept a
comma-separated string or an array; multiple values are OR'd together.

### Custom authority checks

For anything beyond scope/role, implement `AuthorityCheckInterface` yourself and use apiserver's
`#[RequiresAuthority]` directly:

```php
use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Attributes\RequiresAuthority;
use gijsbos\ApiServer\Interfaces\AuthorityCheckInterface;

class IsAccountOwnerCheck implements AuthorityCheckInterface
{
    public function execute(Route $route) : void
    {
        // Inspect $route->getData() (or look anything else up yourself),
        // throw to deny, return normally to allow.
    }
}

#[RequiresAuthority(IsAccountOwnerCheck::class)]
```

`HasScope` and `HasRole` are themselves just `RequiresAuthority` subclasses that supply `ScopeVerifier` /
`RoleVerifier` as the check — following the same pattern is the intended way to extend authorization
beyond what this package ships.

## Components

| Class | Purpose |
| --- | --- |
| `OAuth2Server` | Extends `Server`; wires OAuth2 bearer-token verification from a registered policy. |
| `AccessTokenVerificationPolicy` | Configures issuer, key source, audience, allowed algorithms, `kid` requirement. |
| `AccessTokenVerifier` | Verifies a JWT's header, signature, and standard claims (`exp`, `nbf`, `iss`, `aud`) against a policy. |
| `JwksResolver` | Fetches public keys directly, from a URL, or via OpenID Connect discovery; caches in APCu when available. |
| `SystemClock` | PSR-20 clock used for `exp`/`nbf` checks (injectable for testing). |
| `HasScope` / `ScopeVerifier` | Route attribute + backing check for scope-gated authorization. |
| `HasRole` / `RoleVerifier` | Route attribute + backing check for role-gated authorization. |

## Contributions

Contributions are welcome!
Please open an issue or submit a pull request following our contribution guidelines.
