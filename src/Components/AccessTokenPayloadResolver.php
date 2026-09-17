<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Authentication\AuthenticationHeaderParser;
use gijsbos\ApiServer\OAuth2\OAuth2Server;
use gijsbos\Http\Exceptions\UnauthorizedException;

/**
 * AccessTokenPayloadResolver
 *  Parses the current request's Authorization header and verifies it as an
 *  OAuth2 access token, returning the decoded payload. Shared by
 *  ScopeVerifier and RoleVerifier so the parse-and-verify step - which is
 *  OAuth2-specific and has no business living in the generic apiserver
 *  package - isn't duplicated between them.
 */
final class AccessTokenPayloadResolver
{
    public static function resolve() : array
    {
        $credentials = new AuthenticationHeaderParser()->parse();

        if($credentials === null)
            throw new UnauthorizedException("authorizationRequired", "Authorization required");

        $policy = OAuth2Server::getAccessTokenVerificationPolicy();

        return new AccessTokenVerifier($policy)->verify($credentials->value);
    }
}
