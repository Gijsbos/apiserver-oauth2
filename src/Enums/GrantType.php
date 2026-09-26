<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Enums;

use InvalidArgumentException;

/**
 * GrantType
 *  The standard OAuth 2.0 grant types, the values are the grant_type values of a token request:
 *      AuthorizationCode   - RFC 6749 §4.1 (with PKCE, RFC 7636)
 *      ClientCredentials   - RFC 6749 §4.4
 *      Password            - RFC 6749 §4.3, discouraged by RFC 9700, removed in OAuth 2.1
 *      RefreshToken        - RFC 6749 §6
 *      JwtBearer           - RFC 7523 §2.1, a JWT (e.g. an id_token) as authorization grant
 *      DeviceCode          - RFC 8628, devices without a browser
 *      TokenExchange       - RFC 8693
 *  Implicit (RFC 6749 §4.2) is not a case: OAuth 2.1 and RFC 9700 remove it, tokens in URLs leak.
 *  Extension grants of a server (RFC 6749 §4.5) are absolute URIs of that server and not part of this enum.
 */
enum GrantType : string
{
    case AuthorizationCode = "authorization_code";
    case ClientCredentials = "client_credentials";
    case Password = "password";
    case RefreshToken = "refresh_token";
    case JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    case DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    case TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";

    /**
     * values
     *  The grant_type values of $grantTypes
     */
    public static function values(array $grantTypes) : array
    {
        return array_map(fn(GrantType $grantType) => $grantType->value, $grantTypes);
    }

    /**
     * fromList
     *  Parses a comma separated list of grant_type values, throws on an unknown value
     *
     * @return GrantType[]
     */
    public static function fromList(string $grantTypes) : array
    {
        $result = [];

        foreach(preg_split("/\s*,\s*/", trim($grantTypes), -1, PREG_SPLIT_NO_EMPTY) as $value)
        {
            $grantType = self::tryFrom($value);

            if($grantType === null)
                throw new InvalidArgumentException("Grant type \"$value\" is unknown");

            $result[$grantType->value] = $grantType;
        }

        return array_values($result);
    }
}
