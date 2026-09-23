<?php
declare(strict_types=1);

use gijsbos\ApiServer\Attributes\GetRoute;
use gijsbos\ApiServer\Classes\RequestHeader;
use gijsbos\ApiServer\Attributes\ReturnFilter;
use gijsbos\ApiServer\OAuth2\Attributes\HasRole;
use gijsbos\ApiServer\OAuth2\Attributes\HasScope;
use gijsbos\ApiServer\RouteController;

/**
 * TestController
 */
class TestController extends RouteController
{
    /**
     * hasScope
     */
    #[GetRoute('/test/hasscope')]
    #[ReturnFilter(['token'])]
    #[HasScope("test-scope")]
    public function hasScope(
        RequestHeader|string $authorization = new RequestHeader(),
    )
    {
        return [
            "token" => $authorization,
        ];
    }

    /**
     * hasRole
     */
    #[GetRoute('/test/hasrole')]
    #[ReturnFilter(['token'])]
    #[HasRole("test-role")]
    public function hasRole(
        RequestHeader|string $authorization = new RequestHeader(),
    )
    {
        return [
            "token" => $authorization,
        ];
    }

    /**
     * hasAnyScope - comma-separated required scopes (OR)
     */
    #[GetRoute('/test/hasanyscope')]
    #[ReturnFilter(['ok'])]
    #[HasScope("read, write")]
    public function hasAnyScope()
    {
        return ["ok" => true];
    }

    /**
     * hasScopeArray - array of required scopes (OR)
     */
    #[GetRoute('/test/hasscopearray')]
    #[ReturnFilter(['ok'])]
    #[HasScope(["read", "write"])]
    public function hasScopeArray()
    {
        return ["ok" => true];
    }

    /**
     * hasAnyRole - comma-separated required roles (OR)
     */
    #[GetRoute('/test/hasanyrole')]
    #[ReturnFilter(['ok'])]
    #[HasRole("admin, editor")]
    public function hasAnyRole()
    {
        return ["ok" => true];
    }

    /**
     * hasRoleArray - array of required roles (OR)
     */
    #[GetRoute('/test/hasrolearray')]
    #[ReturnFilter(['ok'])]
    #[HasRole(["admin", "editor"])]
    public function hasRoleArray()
    {
        return ["ok" => true];
    }

    /**
     * hasNoUsableScope - only empty entries, can never be satisfied
     */
    #[GetRoute('/test/hasnousablescope')]
    #[ReturnFilter(['ok'])]
    #[HasScope(" , ")]
    public function hasNoUsableScope()
    {
        return ["ok" => true];
    }

    /**
     * hasScopeAndRole - both attributes must pass
     */
    #[GetRoute('/test/hasscopeandrole')]
    #[ReturnFilter(['ok'])]
    #[HasScope("test-scope")]
    #[HasRole("test-role")]
    public function hasScopeAndRole()
    {
        return ["ok" => true];
    }

    /**
     * publicRoute - no authority attribute, SecurityContext permits it without auth
     */
    #[GetRoute('/test/public')]
    #[ReturnFilter(['ok'])]
    public function publicRoute()
    {
        return ["ok" => true];
    }

    /**
     * jwks - serves the public example key set (target for CertificateProvider "keysUri")
     */
    #[GetRoute('/test/idp/jwks')]
    #[ReturnFilter(['keys'])]
    public function jwks()
    {
        return ["keys" => [EXAMPLE_KEY_SET->toPublic()->all()]];
    }

    /**
     * openIdConfiguration - serves OIDC discovery for issuer "{BASE_URL}/test/idp"
     */
    #[GetRoute('/test/idp/.well-known/openid-configuration')]
    #[ReturnFilter(['issuer', 'jwks_uri'])]
    public function openIdConfiguration()
    {
        $issuer = rtrim(env("BASE_URL"), "/") . "/test/idp";

        return [
            "issuer" => $issuer,
            "jwks_uri" => "$issuer/jwks",
        ];
    }
}