<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Certificate;

use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;

use gijsbos\Http\Exceptions\InternalServerErrorException;
use gijsbos\Http\Http\HTTPRequest;
use gijsbos\Http\Exceptions\UnauthorizedException;

use Override;

/**
 * CertificateProvider
 *  Provides the policy's keys directly, or fetches an issuer's public keys either from
 *  a JWKS URL or via OpenID Connect discovery: {issuerUri}/.well-known/openid-configuration -> jwks_uri.
 *  Fetched keys are cached in APCu (when available) per keysUri / issuerUri for $CACHE_TTL_SECONDS.
 */
class CertificateProvider implements CertificateProviderInterface
{
    const WELL_KNOWN_OPEN_ID_PATH = '/.well-known/openid-configuration';

    /**
     * Time keys stay cached in APCu before a fresh fetch is forced.
     * Key rotations are normally done with an overlap window measured in
     * days, so an hour-long cache keeps request volume down without risking
     * a long window of trusting a revoked key.
     */
    public static $CACHE_TTL_SECONDS = 3600;

    public function __construct(
        private AccessTokenVerificationPolicy $accessTokenVerificationPolicy,
    )
    {}

    private function storeInApcuCache(string $uri, array $keys)
    {
        if(function_exists('apcu_fetch') && function_exists('apcu_store'))
        {
            \apcu_store($uri, $keys, self::$CACHE_TTL_SECONDS);
        }
    }

    private function retrieveFromApcuCache(string $uri)
    {
        if(function_exists('apcu_fetch') && function_exists('apcu_store')) // fetch from instance memory
        {
            $keys = \apcu_fetch($uri, $success);

            if($success)
            {
                return $keys;
            }
        }

        return null;
    }

    private function fetchKeysFromKeysUri(string $keysUri) : array
    {
        $response = HTTPRequest::get(["uri" => $keysUri]);

        if(!$response->isSuccessful())
            throw new UnauthorizedException("tokenKeysUnavailable", "Could not retrieve public keys from \"$keysUri\"");

        $data = $response->getParameters();

        if(!CertificateSet::arrayIsCertificateSet($data))
            throw new UnauthorizedException("tokenKeysUnavailable", "Public keys response from \"$keysUri\" did not contain a \"keys\" array");

        return ["keys" => $data["keys"]];
    }

    private function resolveKeysUriFromIssuerUri(string $issuerUri) : string
    {
        $wellKnownUri = rtrim($issuerUri, '/') . self::WELL_KNOWN_OPEN_ID_PATH;

        $response = HTTPRequest::get(["uri" => $wellKnownUri]);

        if(!$response->isSuccessful())
            throw new UnauthorizedException("tokenIssuerUnavailable", "Could not retrieve OpenID configuration from \"$wellKnownUri\"");

        $jwksUri = $response->getParameter("jwks_uri");

        if(!is_string($jwksUri) || strlen($jwksUri) == 0)
            throw new UnauthorizedException("tokenIssuerUnavailable", "OpenID configuration at \"$wellKnownUri\" is missing \"jwks_uri\"");

        return $jwksUri;
    }

    #[Override]
    public function provide() : CertificateSet
    {
        if($this->accessTokenVerificationPolicy->keys !== null)
        {
            return CertificateSet::createFromArray($this->accessTokenVerificationPolicy->keys);
        }

        if($this->accessTokenVerificationPolicy->keysUri)
        {
            $cachedKeysData = $this->retrieveFromApcuCache($this->accessTokenVerificationPolicy->keysUri);

            if($cachedKeysData !== null)
                return CertificateSet::createFromArray($cachedKeysData);

            $certificateData = $this->fetchKeysFromKeysUri($this->accessTokenVerificationPolicy->keysUri);

            $this->storeInApcuCache($this->accessTokenVerificationPolicy->keysUri, $certificateData);

            return CertificateSet::createFromArray($certificateData);
        }

        if($this->accessTokenVerificationPolicy->issuerUri)
        {
            $cachedKeysData = $this->retrieveFromApcuCache($this->accessTokenVerificationPolicy->issuerUri);

            if($cachedKeysData !== null)
                return CertificateSet::createFromArray($cachedKeysData);

            $keysUri = $this->resolveKeysUriFromIssuerUri($this->accessTokenVerificationPolicy->issuerUri);

            $certificateData = $this->fetchKeysFromKeysUri($keysUri);

            $this->storeInApcuCache($this->accessTokenVerificationPolicy->issuerUri, $certificateData);

            return CertificateSet::createFromArray($certificateData);
        }

        throw new InternalServerErrorException("certificateProviderMisconfigured", "No certificate has been configured");
    }
}