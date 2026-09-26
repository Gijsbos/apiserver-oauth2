<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

/**
 * AccessTokenClaimToListConverter
 */
abstract class AccessTokenClaimToListConverter
{
    /**
     * convert
     *  Normalises a scope/role claim to a list of non-empty strings. Issuers emit
     *  these claims either as a delimited string (space per RFC 6749 §3.3, comma
     *  tolerated) or as a JSON array of strings. Returns null when the claim is
     *  neither, or is an array holding anything but strings - callers treat that
     *  as malformed and deny.
     */
    public static function convert(mixed $claim) : null|array
    {
        if(is_string($claim))
            return preg_split('/[ ,]+/', $claim, -1, PREG_SPLIT_NO_EMPTY);

        if(!is_array($claim))
            return null;

        foreach($claim as $value)
            if(!is_string($value))
                return null;

        return array_values(array_filter($claim, fn(string $value) => $value !== ""));
    }
}