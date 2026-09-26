<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * OAuth2VerificationPolicy
 *  Configures how AccessTokenVerifier accepts a JWT - separate from
 *  SecurityContext, which only decides whether a path needs a token at all.
 *
 *  Key source, in order of preference:
 *  keys       - raw JWKS data provided directly, as {"keys": [...]}. Skips
 *               discovery and any HTTP fetch.
 *  keysUri    - a direct JWKS URL, skipping discovery. When set without issuerUri,
 *               "iss" is not validated (no canonical issuer to check against) -
 *               matching how e.g. Spring Security's withJwkSetUri() behaves.
 *  issuerUri  - used for OIDC discovery (.well-known/openid-configuration -> jwks_uri)
 *               and, when set, to validate the token's "iss" claim.
 *  audience   - when set, the token's "aud" claim is required to contain it.
 *
 *  At least one of keys/keysUri/issuerUri is required, checked by CertificateProvider::provide()
 *  when the keys are first needed rather than here. Setting issuerUri
 *  alongside keys/keysUri still validates "iss" even though it isn't used
 *  to locate the keys.
 */
final class OAuth2VerificationPolicy
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
        public array $metadata = [],
    )
    {
        if(count($this->allowedAlgorithms) == 0)
            throw new \InvalidArgumentException("OAuth2VerificationPolicy \"allowedAlgorithms\" must contain at least one algorithm");

        if(count(array_filter($this->allowedAlgorithms, fn($algorithm) => $algorithm instanceof SignatureAlgorithm == false)) > 0)
            throw new \InvalidArgumentException("OAuth2VerificationPolicy \"allowedAlgorithms\" must only contain SignatureAlgorithm instances");
    }

    public function addMetadata(string $key, $value)
    {
        $this->metadata[$key] = $value;
    }

    public function getMetadata(string $key)
    {
        return $this->metadata[$key] ?? null;
    }

    public function hasMetadata(string $key)
    {
        return array_key_exists($key, $this->metadata);
    }
}
