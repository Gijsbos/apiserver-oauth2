<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Interfaces;

/**
 * TokenPayloadInterface
 */
interface TokenPayloadInterface
{
    public static function isClaimRequired(string $name) : bool;

    public static function getRequiredClaims() : array;

    public function getIss() : null|string;

    public function getSub() : null|string;

    public function hasSub() : bool;

    public function getAud() : null|string|array;

    public function hasAnyAudience(string|array $audiences) : bool;

    public function getExp() : null|int;

    public function getNbf() : null|int;

    public function getIat() : null|int;

    public function getJti() : null|string;

    public function getScope() : null|array;

    public function getScopeString() : null|string;

    public function getRoles() : null|array;

    public function getRolesString() : null|string;

    public function getClaim(string $name) : mixed;

    public function addCustomClaim(string $name, $value);

    public function hasCustomClaim(string $name) : bool;

    public function getCustomClaim(string $name);

    public function toArray() : array;

    public static function createFromArray(array $payload) : static;

    public function addMetadata(string $key, $value);

    public function getMetadata(string $key);

    public function hasMetadata(string $key) : bool;
}
