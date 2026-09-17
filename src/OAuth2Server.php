<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2;

use gijsbos\ApiServer\Authentication\AuthenticationVerifier;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;


/**
 * OAuth2Server
 */
class OAuth2Server extends \gijsbos\ApiServer\Server
{
    public function __construct(
        AccessTokenVerificationPolicy $accessTokenVerificationPolicy,
        array $opts = [],
    )
    {
        parent::__construct($opts);

        $this->setAuthenticationVerifier(new AuthenticationVerifier(
            viaBearer: fn($accessToken) => new AccessTokenVerifier($accessTokenVerificationPolicy)->verify($accessToken)
        ));
    }
}