<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\Http\Http\HTTPRequest;
use gijsbos\Http\Exceptions\UnauthorizedException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * JwksResolver
 *  Fetches an issuer's public keys, either directly from a JWKS URL or via
 *  OpenID Connect discovery: {issuerUri}/.well-known/openid-configuration -> jwks_uri.
 *  Keys are cached per keysUri for the lifetime of the resolver instance.
 */
final class JwksResolver
{
    const WELL_KNOWN_OPEN_ID_PATH = '/.well-known/openid-configuration';

    /**
     * Time keys stay cached in APCu before a fresh fetch is forced.
     * Key rotations are normally done with an overlap window measured in
     * days, so an hour-long cache keeps request volume down without risking
     * a long window of trusting a revoked key.
     */
    private const CACHE_TTL_SECONDS = 3600;

    private array $keysByUri;

    public function __construct(
        private AccessTokenVerificationPolicy $policy
    )
    {
        $this->keysByUri = [];
    }

    private function resolveKeysUriFromIssuerUri() : string
    {
        $issuerUri = $this->policy->issuerUri;

        $wellKnownUri = rtrim($issuerUri, '/') . self::WELL_KNOWN_OPEN_ID_PATH;

        $response = HTTPRequest::get(["uri" => $wellKnownUri]);

        if(!$response->isSuccessful())
            throw new UnauthorizedException("tokenIssuerUnavailable", "Could not retrieve OpenID configuration from \"$wellKnownUri\"");

        $jwksUri = $response->getParameter("jwks_uri");

        if(!is_string($jwksUri) || strlen($jwksUri) == 0)
            throw new UnauthorizedException("tokenIssuerUnavailable", "OpenID configuration at \"$wellKnownUri\" is missing \"jwks_uri\"");

        return $jwksUri;
    }

    private function fetchKeys(string $keysUri) : array
    {
        $response = HTTPRequest::get(["uri" => $keysUri]);

        if(!$response->isSuccessful())
            throw new UnauthorizedException("tokenKeysUnavailable", "Could not retrieve public keys from \"$keysUri\"");

        $keys = $response->getParameter("keys");

        if(!is_array($keys))
            throw new UnauthorizedException("tokenKeysUnavailable", "Public keys response from \"$keysUri\" did not contain a \"keys\" array");

        return $keys;
    }

    public static function convertToJWKSet(string|array|JWK|JWKSet $jwk) : JWKSet
    {
        $jwk = is_string($jwk) && is_json($jwk) ? json_decode($jwk, true) : $jwk;
        
        if(is_array($jwk))
        {
            if(array_key_exists("keys", $jwk))
                return JWKSet::createFromKeyData($jwk);
            else
            {
                if(array_is_list($jwk))
                    return JWKSet::createFromKeyData(["keys" => $jwk]);
                else
                {
                    if(!array_key_exists("kty", $jwk))
                        throw new UnauthorizedException("tokenKeyInvalid", "JWK is missing a required \"kty\" claim");

                    $jwk = new JWK($jwk);
                }
            }
        }

        if($jwk instanceof JWK)
        {
            $jwk = new JWKSet([$jwk]);
        }

        return $jwk;
    }

    public function getKeys() : JWKSet
    {
        if($this->policy->keys !== null)
            return self::convertToJWKSet($this->policy->keys);

        $uri = $this->policy->keysUri ?? $this->policy->issuerUri;
        $isIssuerUri = $this->policy->keysUri === null;

        return $this->getKeysFromUri($uri, $isIssuerUri);
    }

    public function getKey(string $kid) : JWK
    {
        return $this->getKeys()->get($kid);
    }

    private function getKeysFromUri(string $uri, bool $isIssuerUri) : JWKSet
    {
        if(function_exists('apcu_fetch') && function_exists('apcu_store')) // fetch from instance memory
        {
            $keys = \apcu_fetch($uri, $success);

            if($success)
            {
                return self::convertToJWKSet($keys);
            }
        }

        if(!array_key_exists($uri, $this->keysByUri))
        {
            $keysUri = $isIssuerUri ? $this->resolveKeysUriFromIssuerUri() : $this->policy->keysUri;

            $this->keysByUri[$uri] = $this->fetchKeys($keysUri);
        }

        $keys = $this->keysByUri[$uri];

        if(function_exists('apcu_fetch') && function_exists('apcu_store'))
        {
            \apcu_store($uri, $keys, self::CACHE_TTL_SECONDS);
        }

        return self::convertToJWKSet($keys);
    }
}
