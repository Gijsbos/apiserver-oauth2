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
 *  Empty entries are ignored; a HasRole without any role can never be satisfied,
 *  so the route is always denied.
 */
#[Attribute(Attribute::TARGET_METHOD)]
class HasRole extends RequiresAuthority
{
    public function __construct(string|array $roles)
    {
        $requiredRoles = array_values(array_filter(
            array_map('trim', is_array($roles) ? $roles : explode(',', $roles)),
            fn($value) => $value !== ""
        ));

        parent::__construct(RoleVerifier::class, $requiredRoles);
    }
}
