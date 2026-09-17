<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Authentication\AuthenticationHeaderParser;
use gijsbos\ApiServer\Authentication\AuthenticationVerifier;
use gijsbos\Http\Exceptions\UnauthorizedException;

/**
 * AccessTokenPayloadExtracter
 */
abstract class AccessTokenPayloadExtracter
{   
    public static function extract(AuthenticationVerifier $authenticationVerifier) : array
    {
        $credentials = new AuthenticationHeaderParser()->parse();

        if($credentials === null)
            throw new UnauthorizedException("authorizationRequired", "Authorization required");

        return $authenticationVerifier->verify($credentials);
    }
}