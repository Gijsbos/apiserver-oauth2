<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use gijsbos\ApiServer\Attributes\Route;
use gijsbos\ApiServer\Interfaces\AuthorityCheckInterface;
use gijsbos\Http\Exceptions\ForbiddenException;

/**
 * ScopeVerifier
 *  Checks the current request's access token "scope" claim against a
 *  required set of scopes (OR - any one match is sufficient).
 */
final class ScopeVerifier implements AuthorityCheckInterface
{
    public function __construct(
        private array $requiredScopes
    )
    { }

    public function execute(Route $route) : void
    {
        $payload = AccessTokenPayloadResolver::resolve();

        if(array_key_exists("scp", $payload))
            $payloadScopes = $payload["scp"];
        else if(array_key_exists("scopes", $payload))
            $payloadScopes = $payload["scopes"];
        else if(array_key_exists("scope", $payload))
            $payloadScopes = $payload["scope"];
        else
            throw new ForbiddenException("insufficient_scope", "The access token does not contain a \"scope\" claim");

        if(!is_string($payloadScopes))
            throw new ForbiddenException("insufficient_scope", "The access token's \"scope\" claim is malformed");

        $payloadScopes = explode(" ", str_replace(",", " ", $payloadScopes)); // RFC 6749 §3.3: scope is space-delimited

        AccessTokenVerifier::verifyHasAuthority(
            $payloadScopes,
            $this->requiredScopes,
            "insufficient_scope",
            "The request requires higher privileges than provided by the access token"
        );
    }
}
