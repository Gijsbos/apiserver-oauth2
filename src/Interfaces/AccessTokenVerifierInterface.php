<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Interfaces;

use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;
use gijsbos\ApiServer\OAuth2\ValueObjects\TokenPayload;

/**
 * AccessTokenVerifierInterface
 */
interface AccessTokenVerifierInterface
{
    public function verify(OAuth2VerificationPolicy $oAuth2VerificationPolicy, string $accessToken) : TokenPayload;
}