<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\ValueObjects;

/**
 * JwtPayload
 *  TokenPayload with the registered JWT claims (RFC 7519 §4.1) required,
 *  "scope" and "roles" remain optional
 */
class JwtPayload extends TokenPayload
{
    protected const array REQUIRED_CLAIMS = ["iss", "sub", "exp", "nbf", "iat", "jti"];

    /**
     * from
     *  Creates a JwtPayload from a TokenPayload, copies all claims and metadata,
     *  throws an InvalidArgumentException when a required claim is missing.
     *  A JwtPayload is returned as is
     */
    public static function from(TokenPayload $tokenPayload) : JwtPayload
    {
        if($tokenPayload instanceof JwtPayload)
            return $tokenPayload;

        $jwtPayload = static::createFromArray($tokenPayload->toArray());

        foreach($tokenPayload->getAllMetadata() as $key => $value)
            $jwtPayload->addMetadata($key, $value);

        return $jwtPayload;
    }
}
