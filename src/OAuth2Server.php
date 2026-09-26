<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2;

use gijsbos\ApiServer\Authorization\AuthorizationHeaderVerifier;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateProvider;
use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;

/**
 * OAuth2Server
 */
class OAuth2Server extends \gijsbos\ApiServer\Server
{
    public function __construct(
        OAuth2VerificationPolicy $oAuth2VerificationPolicy,
        array $opts = [],
    )
    {
        parent::__construct($opts);

        $this->setAuthorizationHeaderVerifier(new AuthorizationHeaderVerifier(
            viaBearer: fn($accessToken) => new AccessTokenVerifier(
                new CertificateProvider()
            )->verify($oAuth2VerificationPolicy, $accessToken)
        ));
    }
}