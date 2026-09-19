<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Interfaces\AuthorityCheckInterface;
use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\InternalServerErrorException;

/**
 * RoleVerifier
 *  Checks the current request's access token "role"/"roles" claim against a
 *  required set of roles (OR - any one match is sufficient). Roles are not
 *  part of the OAuth2 spec (unlike "scope", RFC 6749 §3.3), so there is no
 *  RFC-standard error code here - "insufficient_role" is a self-documenting,
 *  non-standard code chosen to mirror "insufficient_scope" (RFC 6750 §3.1).
 */
final class RoleVerifier implements AuthorityCheckInterface
{
    public function __construct()
    { }

    public function execute(Route $route, array $requiredRoles) : void
    {
        $authenticationVerifier = $route->getServer()->getAuthenticationVerifier();

        if(!$authenticationVerifier)
            throw new InternalServerErrorException("authenticationVerifierNotSet", "Cannot verify scope, an instance of authenticationVerifier must be initialised");

        $payload = AccessTokenPayloadExtracter::extract($authenticationVerifier);

        if(array_key_exists("roles", $payload))
            $payloadRoles = $payload["roles"];
        else if(array_key_exists("role", $payload))
            $payloadRoles = $payload["role"];
        else
            throw new ForbiddenException("insufficientRole", "The access token does not contain a \"role\" claim");

        // Role claims commonly appear as a JSON array; fall back to a
        // delimited string (comma or space) since some issuers use that too.
        if(is_string($payloadRoles))
            $payloadRoles = explode(" ", str_replace(",", " ", $payloadRoles));
        else if(!is_array($payloadRoles))
            throw new ForbiddenException("insufficientRole", "The access token's \"role\" claim is malformed");

        AccessTokenVerifier::verifyHasAuthority(
            $payloadRoles,
            $requiredRoles,
            "insufficientRole",
            "The request requires a role not granted by the access token"
        );
    }
}
