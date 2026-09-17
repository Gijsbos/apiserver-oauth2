<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * AccessTokenVerificationPolicy
 *  Configures how AccessTokenVerifier accepts a JWT - separate from
 *  SecurityContext, which only decides whether a path needs a token at all.
 *
 *  Key source, in order of preference:
 *  keys       - raw JWK/JWKS data provided directly (a JWKS array, a list of
 *               JWKs, or a single JWK). Skips discovery and any HTTP fetch.
 *  keysUri    - a direct JWKS URL, skipping discovery. When set without issuerUri,
 *               "iss" is not validated (no canonical issuer to check against) -
 *               matching how e.g. Spring Security's withJwkSetUri() behaves.
 *  issuerUri  - used for OIDC discovery (.well-known/openid-configuration -> jwks_uri)
 *               and, when set, to validate the token's "iss" claim.
 *  audience   - when set, the token's "aud" claim is required to contain it.
 *
 *  At least one of keys/keysUri/issuerUri is required. Setting issuerUri
 *  alongside keys/keysUri still validates "iss" even though it isn't used
 *  to locate the keys.
 */
final class AccessTokenVerificationPolicy
{
    public function __construct(
        public readonly ?string $issuerUri = null,
        public readonly ?string $keysUri = null,
        public readonly ?array $keys = null,
        public readonly ?string $audience = null,
        public readonly array $allowedAlgorithms = [
            new RS256()
        ],
        public readonly bool $kidRequired = false,
    )
    {
        if($this->issuerUri === null && $this->keysUri === null && $this->keys === null)
            throw new \InvalidArgumentException("AccessTokenVerificationPolicy requires at least one of \"keys\", \"keysUri\" or \"issuerUri\"");

        if(count(array_filter($this->allowedAlgorithms, fn($algorithm) => $algorithm instanceof SignatureAlgorithm == false)) > 0)
            throw new \InvalidArgumentException("AccessTokenVerificationPolicy \"allowedAlgorithms\" must only contain SignatureAlgorithm instances");
    }
}
