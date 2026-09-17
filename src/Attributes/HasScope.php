<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Attributes;

use Attribute;
use gijsbos\ApiServer\Attributes\RequiresAuthority;
use gijsbos\ApiServer\OAuth2\Components\ScopeVerifier;

/**
 * HasScope
 *  Requires the access token's "scope" claim to contain at least one of the
 *  given scopes (OR). $scopes accepts a comma-separated string or an array.
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasScope extends RequiresAuthority
{
    public function __construct(string|array $scopes)
    {
        $requiredScopes = is_array($scopes) ? $scopes : array_map('trim', explode(',', $scopes));

        parent::__construct(fn() => new ScopeVerifier($requiredScopes));
    }
}
