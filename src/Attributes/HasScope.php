<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Attributes;

use Attribute;
use gijsbos\ApiServer\Attributes\RequiresAuthority;
use gijsbos\ApiServer\OAuth2\Components\ScopeVerifier;

/**
 * HasScope
 *  Requires the access token's scope claim ("scp", "scopes" or "scope") to contain
 *  at least one of the given scopes (OR). $scopes accepts a comma-separated string
 *  or an array. Empty entries are ignored; a HasScope without any scope can never
 *  be satisfied, so the route is always denied.
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasScope extends RequiresAuthority
{
    public function __construct(string|array $scopes)
    {
        $requiredScopes = array_values(array_filter(
            array_map('trim', is_array($scopes) ? $scopes : explode(',', $scopes)),
            fn($value) => $value !== ""
        ));

        parent::__construct(ScopeVerifier::class, $requiredScopes);
    }
}