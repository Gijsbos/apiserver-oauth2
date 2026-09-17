<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2;

use gijsbos\ApiServer\Authentication\AuthenticationVerifier;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;
use gijsbos\Http\Exceptions\InternalServerErrorException;

/**
 * OAuth2Server
 */
class OAuth2Server extends \gijsbos\ApiServer\Server
{
    public static null|array $accessTokenVerificationPolicies = null;

    public function __construct(array $opts = [])
    {
        parent::__construct($opts);

        $this->initViaBearerHook();
    }

    /**
     * Initialise the viaBearerHook used in OAuth2
     */
    private function initViaBearerHook() : void
    {
        $accessTokenVerificationPolicy = self::getAccessTokenVerificationPolicy();

        if($accessTokenVerificationPolicy instanceof AccessTokenVerificationPolicy === false)
            throw new InternalServerErrorException(
                "accessTokenVerificationPolicyMissing",
                "No AccessTokenVerificationPolicy is registered - call OAuth2Server::addAccessTokenVerificationPolicy() before starting the server"
            );

        AuthenticationVerifier::$viaBearer = fn($accessToken) => new AccessTokenVerifier($accessTokenVerificationPolicy)->verify($accessToken);
    }

    /**
     * Allow using multiple access token verification policies
     */
    public static function addAccessTokenVerificationPolicy(AccessTokenVerificationPolicy $accessTokenVerificationPolicy, string $key = "default")
    {
        if(self::$accessTokenVerificationPolicies == null)
            self::$accessTokenVerificationPolicies = [];

        self::$accessTokenVerificationPolicies[$key] = $accessTokenVerificationPolicy;
    }

    /**
     * Fetch access token verification policy, using 'default' key as default
     */
    public static function getAccessTokenVerificationPolicy(string $key = "default")
    {
        if(!array_key_exists($key, self::$accessTokenVerificationPolicies ?? []))
            throw new InternalServerErrorException("accessTokenVerificationPolicyNotFound", "No accessTokenVerificationPolicy found with key \"$key\"");

        return self::$accessTokenVerificationPolicies[$key];
    }
}