<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Interfaces\RouteAuthorityVerifierInterface;
use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\InternalServerErrorException;

/**
 * RoleVerifier
 *  Checks the current request's access token "role"/"roles" claim against a
 *  required set of roles (OR - any one match is sufficient). Roles are not
 *  part of the OAuth2 spec (unlike "scope", RFC 6749 §3.3), so there is no
 *  RFC-standard error code here - "insufficientRole" is a self-documenting,
 *  non-standard code chosen to mirror "insufficientScope", the camelCase form of
 *  RFC 6750 §3.1's "insufficient_scope" (this package uses camelCase error codes
 *  throughout). "roles" takes precedence over "role" when both are present.
 */
final class RoleVerifier implements RouteAuthorityVerifierInterface
{
    public function __construct()
    { }

    public function execute(Route $route, array $requiredRoles)
    {
        $payload = $route->getServer()->getAuthorizationResult();

        if(!is_array($payload))
            throw new InternalServerErrorException("authenticationResultEmpty", "Cannot verify role, authentication result data empty");

        if(array_key_exists("roles", $payload))
            $payloadRoles = $payload["roles"];
        else if(array_key_exists("role", $payload))
            $payloadRoles = $payload["role"];
        else
            throw new ForbiddenException("insufficientRole", "The access token does not contain a \"role\" claim");

        // Role claims commonly appear as a JSON array; a delimited string
        // (comma or space) is accepted too since some issuers use that.
        $payloadRoles = AccessTokenClaimToListConverter::convert($payloadRoles);

        if($payloadRoles === null)
            throw new ForbiddenException("insufficientRole", "The access token's \"role\" claim is malformed");

        AccessTokenVerifier::verifyHasAuthority(
            $payloadRoles,
            $requiredRoles,
            "insufficientRole",
            "The request requires a role not granted by the access token"
        );
    }
}