<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Interfaces\RouteAuthorityVerifierInterface;
use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\InternalServerErrorException;

/**
 * ScopeVerifier
 *  Checks the current request's access token scope claim ("scp", "scopes" or
 *  "scope", first one present wins) against a required set of scopes (OR - any
 *  one match is sufficient). The claim may be a delimited string (RFC 6749 §3.3)
 *  or a JSON array of strings. Denies with "insufficientScope".
 */
final class ScopeVerifier implements RouteAuthorityVerifierInterface
{
    public function __construct()
    { }

    public function execute(Route $route, array $requiredScopes)
    {
        $payload = $route->getServer()->getAuthorizationResult();

        if(!is_array($payload))
            throw new InternalServerErrorException("authenticationResultEmpty", "Cannot verify scope, authentication result data empty");

        if(array_key_exists("scp", $payload))
            $payloadScopes = $payload["scp"];
        else if(array_key_exists("scopes", $payload))
            $payloadScopes = $payload["scopes"];
        else if(array_key_exists("scope", $payload))
            $payloadScopes = $payload["scope"];
        else
            throw new ForbiddenException("insufficientScope", "The access token does not contain a \"scope\" claim");

        $payloadScopes = AccessTokenClaimToListConverter::convert($payloadScopes);

        if($payloadScopes === null)
            throw new ForbiddenException("insufficientScope", "The access token's \"scope\" claim is malformed");

        AccessTokenVerifier::verifyHasAuthority(
            $payloadScopes,
            $requiredScopes,
            "insufficientScope",
            "The request requires higher privileges than provided by the access token"
        );
    }
}