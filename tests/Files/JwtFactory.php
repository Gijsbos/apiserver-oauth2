<?php
declare(strict_types=1);

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Core\Algorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * JwtFactory
 *  Mints JWTs for tests. By default a token is a valid RS256 token signed with
 *  EXAMPLE_KEY_SET, carrying a "kid" header and iss/sub/aud/iat/exp claims.
 *  Pass a null claim value to drop a default claim.
 */
final class JwtFactory
{
    private static ?JWK $foreignKey = null;

    public static function kid() : string
    {
        return EXAMPLE_KEY_SET->get('kid');
    }

    public static function publicKey() : array
    {
        return EXAMPLE_KEY_SET->toPublic()->all();
    }

    /**
     * A key that is NOT part of EXAMPLE_KEY_SET but claims the same "kid",
     * so a token signed with it looks legitimate but has a bad signature.
     */
    public static function foreignKey() : JWK
    {
        return self::$foreignKey ??= JWKFactory::createRSAKey(2048, [
            'kid' => self::kid(),
            'alg' => 'RS256',
            'use' => 'sig',
        ]);
    }

    public static function claims(array $overrides = []) : array
    {
        $claims = array_merge([
            'iss' => 'https://example.com',
            'sub' => 'test-user',
            'aud' => 'test-client',
            'iat' => time(),
            'exp' => time() + 3600,
        ], $overrides);

        return array_filter($claims, fn($value) => $value !== null);
    }

    /**
     * mint
     *  $payload as array: claims merged over the defaults. As string: used verbatim
     *  (e.g. to build a signed token whose payload is not a JSON object).
     *  $header replaces the default header entirely when given.
     */
    public static function mint(
        array|string $payload = [],
        null|array $header = null,
        null|Algorithm $algorithm = null,
        null|JWK $key = null,
    ) : string
    {
        $algorithm ??= new RS256();
        $key ??= EXAMPLE_KEY_SET;
        $header ??= ['alg' => $algorithm->name(), 'kid' => self::kid()];
        $payload = is_array($payload) ? json_encode(self::claims($payload)) : $payload;

        $jws = (new JWSBuilder(new AlgorithmManager([$algorithm])))
            ->create()
            ->withPayload($payload)
            ->addSignature($key, $header)
            ->build();

        return (new CompactSerializer())->serialize($jws);
    }

    /**
     * withReplacedPayload
     *  Swaps the payload segment of an existing token while keeping its signature,
     *  which must make signature verification fail.
     */
    public static function withReplacedPayload(string $jwt, array $payload) : string
    {
        $parts = explode('.', $jwt);
        $parts[1] = rtrim(strtr(base64_encode(json_encode(self::claims($payload))), '+/', '-_'), '=');

        return implode('.', $parts);
    }
}
