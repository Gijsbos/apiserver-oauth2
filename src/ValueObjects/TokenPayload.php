<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\ValueObjects;

use InvalidArgumentException;

use gijsbos\ApiServer\OAuth2\Components\AccessTokenClaimToListConverter;
use gijsbos\ApiServer\OAuth2\Interfaces\TokenPayloadInterface;

/**
 * TokenPayload
 *  Holds the common claims (registered JWT claims, RFC 7519 §4.1, plus "scope" and "roles")
 *  and any custom claims. All common claims are optional here; subclasses mark claims as
 *  required by overriding REQUIRED_CLAIMS, a missing required claim throws an InvalidArgumentException.
 */
class TokenPayload implements TokenPayloadInterface
{
    public const array COMMON_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "roles"];

    protected const array REQUIRED_CLAIMS = [];

    private null|array $scope;
    private null|array $roles;

    public function __construct(
        private null|string $iss = null, // Issuer, OAuth2 provider uri
        private null|string $sub = null, // Subject, userId or clientId
        private null|string|array $aud = null, // Audience, clientId or list of audiences
        private null|int $exp = null, // Expiration time, unix timestamp
        private null|int $nbf = null, // Not before, unix timestamp
        private null|int $iat = null, // Issued at, unix timestamp
        private null|string $jti = null, // JWT id, unique token identifier
        null|string|array $scope = null, // Space delimited string (RFC 6749 §3.3) or list of scopes
        null|string|array $roles = null, // List of roles or delimited string
        private array $customClaims = [],
        private array $metadata = [],
    )
    {
        $this->setAud($aud);

        $this->scope = self::convertToList("scope", $scope);
        $this->roles = self::convertToList("roles", $roles);

        foreach(static::REQUIRED_CLAIMS as $claim)
            if($this->getClaim($claim) === null)
                throw new InvalidArgumentException(sprintf("%s \"%s\" claim is required", (new \ReflectionClass($this))->getShortName(), $claim));
    }

    private static function convertToList(string $claim, null|string|array $value) : null|array
    {
        if($value === null)
            return null;

        $list = AccessTokenClaimToListConverter::convert($value);

        if($list === null)
            throw new InvalidArgumentException("TokenPayload \"$claim\" claim must be a delimited string or a list of strings");

        return $list;
    }

    public static function isClaimRequired(string $name) : bool
    {
        return in_array($name, static::REQUIRED_CLAIMS, true);
    }

    public static function getRequiredClaims() : array
    {
        return static::REQUIRED_CLAIMS;
    }

    public function getIss() : null|string
    {
        return $this->iss;
    }

    public function getSub() : null|string
    {
        return $this->sub;
    }

    public function getAud() : null|string|array
    {
        return $this->aud;
    }

    public function setAud(null|string|array $aud = null)
    {
        if(is_array($aud))
            foreach($aud as $value)
                if(!is_string($value))
                    throw new InvalidArgumentException("TokenPayload \"aud\" claim must be a string or a list of strings");

        $this->aud = $aud;
    }

    public function getExp() : null|int
    {
        return $this->exp;
    }

    public function getNbf() : null|int
    {
        return $this->nbf;
    }

    public function getIat() : null|int
    {
        return $this->iat;
    }

    public function getJti() : null|string
    {
        return $this->jti;
    }

    public function getScope() : null|array
    {
        return $this->scope;
    }

    public function getRoles() : null|array
    {
        return $this->roles;
    }

    /**
     * getClaim
     *  Returns a common or custom claim, null when not set
     */
    public function getClaim(string $name) : mixed
    {
        return match($name)
        {
            "iss" => $this->iss,
            "sub" => $this->sub,
            "aud" => $this->aud,
            "exp" => $this->exp,
            "nbf" => $this->nbf,
            "iat" => $this->iat,
            "jti" => $this->jti,
            "scope" => $this->scope,
            "roles" => $this->roles,
            default => $this->getCustomClaim($name),
        };
    }

    public function addCustomClaim(string $name, $value)
    {
        if(in_array($name, self::COMMON_CLAIMS, true))
            throw new InvalidArgumentException("TokenPayload \"$name\" is a common claim and cannot be added as custom claim");

        $this->customClaims[$name] = $value;
    }

    public function hasCustomClaim(string $name) : bool
    {
        return array_key_exists($name, $this->customClaims);
    }

    public function getCustomClaim(string $name)
    {
        return $this->customClaims[$name] ?? null;
    }

    /**
     * toArray
     *  Custom claims cannot override the common claims, unset claims are left out,
     *  scope is serialized as a space delimited string (RFC 9068 §2.2.3)
     */
    public function toArray() : array
    {
        $claims = [];

        foreach(self::COMMON_CLAIMS as $claim)
            if(($value = $this->getClaim($claim)) !== null)
                $claims[$claim] = $claim === "scope" ? implode(" ", $value) : $value;

        // The + union rather than array_merge, which would renumber numeric custom claim names
        return $claims + $this->customClaims;
    }

    /**
     * createFromArray
     *  Inverse of toArray, all claims other than the common claims are treated as custom claims
     */
    public static function createFromArray(array $payload) : static
    {
        foreach(["iss", "sub", "jti"] as $claim)
            if(isset($payload[$claim]) && !is_string($payload[$claim]))
                throw new InvalidArgumentException("TokenPayload \"$claim\" claim must be a string");

        // NumericDate may be non-integer (RFC 7519 §2), fractions are dropped
        foreach(["exp", "nbf", "iat"] as $claim)
        {
            if(isset($payload[$claim]) && is_float($payload[$claim]))
                $payload[$claim] = (int) $payload[$claim];

            if(isset($payload[$claim]) && !is_int($payload[$claim]))
                throw new InvalidArgumentException("TokenPayload \"$claim\" claim must be a numeric date");
        }

        foreach(["aud", "scope", "roles"] as $claim)
            if(isset($payload[$claim]) && !is_string($payload[$claim]) && !is_array($payload[$claim]))
                throw new InvalidArgumentException("TokenPayload \"$claim\" claim must be a string or a list of strings");

        return new static(
            iss: $payload["iss"] ?? null,
            sub: $payload["sub"] ?? null,
            aud: $payload["aud"] ?? null,
            exp: $payload["exp"] ?? null,
            nbf: $payload["nbf"] ?? null,
            iat: $payload["iat"] ?? null,
            jti: $payload["jti"] ?? null,
            scope: $payload["scope"] ?? null,
            roles: $payload["roles"] ?? null,
            customClaims: array_diff_key($payload, array_flip(self::COMMON_CLAIMS)),
        );
    }

    public function addMetadata(string $key, $value)
    {
        $this->metadata[$key] = $value;
    }

    public function getMetadata(string $key)
    {
        return $this->metadata[$key] ?? null;
    }

    public function getAllMetadata() : array
    {
        return $this->metadata;
    }

    public function hasMetadata(string $key) : bool
    {
        return array_key_exists($key, $this->metadata);
    }
}
