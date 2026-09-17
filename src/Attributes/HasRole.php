<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Attributes;

use Attribute;
use gijsbos\ApiServer\Attributes\RequiresAuthority;
use gijsbos\ApiServer\OAuth2\Components\RoleVerifier;

/**
 * HasRole
 *  Requires the access token's "role"/"roles" claim to contain at least one
 *  of the given roles (OR). $roles accepts a comma-separated string or an array.
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasRole extends RequiresAuthority
{
    public function __construct(string|array $roles)
    {
        $requiredRoles = is_array($roles) ? $roles : array_map('trim', explode(',', $roles));

        parent::__construct(fn() => new RoleVerifier($requiredRoles));
    }
}
