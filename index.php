<?php

use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;
use gijsbos\ApiServer\OAuth2\OAuth2Server;

include_once "tests/Autoload.php";

try
{
    $server = new OAuth2Server(
        new OAuth2VerificationPolicy(
            keys: ["keys" => [EXAMPLE_KEY_SET->toPublic()->all()]],
            kidRequired: true
        )
        ,
        [
            "requireHttps" => false,                // Must use HTTPS or receive error, defaults to false
            "pathPrefix" => "apiserver-oauth2/",    // Used for subpaths e.g. localhost/mysubpath/
            "escapeResult" => true,                 // Escaped special characters, defaults to true
            "addServerTime" => true,                // Adds code execution time
            "addRequestTime" => true,               // Adds total server response time
        ]
    );

    $server->listen();
}
catch(RuntimeException | Exception | TypeError | Throwable $ex)
{
    print($ex->getMessage());
}