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
}