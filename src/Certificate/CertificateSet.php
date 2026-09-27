<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Certificate;

use gijsbos\Http\Exceptions\InternalServerErrorException;
use gijsbos\Http\Exceptions\UnauthorizedException;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * CertificateSet
 */
class CertificateSet
{
    public function __construct(private array $keys)
    { }

    public function getKid(string $kid)
    {
        foreach($this->keys as $key)
            if(is_array($key) && ($key["kid"] ?? null) === $kid)
                return $key;

        return null;
    }

    public function hasKid(string $kid) : bool
    {
        return $this->getKid($kid) !== null;
    }

    public function hasKeys() : bool
    {
        return count($this->keys) > 0;
    }

    public function toKeysData() : array
    {
        return [
            "keys" => $this->keys,
        ];
    }

    /* JWK members that are private (RFC 7518 §6, RFC 8037 §2): never part of a public key */
    const PRIVATE_KEY_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    /**
     * toPublicKeys
     *  The set as public JWK Set {"keys": [...]}, e.g. for a jwks_uri: private members are removed from every key and symmetric
     *  keys (kty "oct", their only material is secret) are left out. Safe to publish whatever keys the set holds.
     */
    public function toPublicKeys() : array
    {
        $keys = [];

        foreach($this->keys as $key)
        {
            if(!is_array($key) || ($key["kty"] ?? null) === "oct")
                continue;

            $keys[] = array_diff_key($key, array_flip(self::PRIVATE_KEY_MEMBERS));
        }

        return [
            "keys" => $keys,
        ];
    }

    public function toJWKSet() : JWKSet
    {
        return self::convertToJWKSet($this->toKeysData());
    }

    private function certificateContainsRequiredKeys(array $certificate)
    {
        return array_key_exists("kid", $certificate);
    }

    /**
     * Adds a single JWK, or every key of a {"keys": [...]} set.
     */
    public function addCertificateData(array $certificateData)
    {
        $certificates = self::arrayIsCertificateSet($certificateData) ? self::keysOf($certificateData) : [$certificateData];

        foreach($certificates as $certificate)
            if(!is_array($certificate) || !$this->certificateContainsRequiredKeys($certificate))
                throw new InternalServerErrorException("malformedCertificate", "Certificate data does not contain required keys kid");

        array_push($this->keys, ...$certificates);
    }

    /**
     * keysOf
     *  The keys of a JWK Set {"keys": [...]} (RFC 7517 §5), null when $data is no JWK Set
     */
    private static function keysOf(array $data) : null|array
    {
        if(!array_key_exists("keys", $data))
            return null;

        return is_array($data["keys"]) && array_is_list($data["keys"]) ? $data["keys"] : null;
    }

    /**
     * arrayIsCertificateSet
     *  A JWK Set {"keys": [...]}, every key a JSON object. An empty set is valid, a bare list of keys is not.
     *  The contents of a key are not checked here: a key that cannot be used (e.g. without "kty") is ignored when keys are
     *  used, it does not make the set unusable (RFC 7517 §5), a token that needs it is rejected then.
     */
    public static function arrayIsCertificateSet(array $data) : bool
    {
        $keys = self::keysOf($data);

        if($keys === null)
            return false;

        foreach($keys as $key)
            if(!is_array($key) || ($key !== [] && array_is_list($key)))
                return false;

        return true;
    }

    /**
     * createFromArray
     *  A JWK Set {"keys": [...]} or a single key, see arrayIsCertificateSet
     */
    public static function createFromArray(array $data)
    {
        // A single key instead of a set: detected by its mandatory "kty" (RFC 7517 §4.1)
        if(array_key_exists("kty", $data))
            $data = ["keys" => [$data]];

        if(!self::arrayIsCertificateSet($data))
            throw new InternalServerErrorException("malformedCertificateSet", "Certificate set is malformed");

        return new self(self::keysOf($data));
    }

    public static function convertToJWKSet(string|array|JWK|JWKSet $jwk) : JWKSet
    {
        $jwk = is_string($jwk) && is_json($jwk) ? json_decode($jwk, true) : $jwk;
        
        if(is_array($jwk))
        {
            if(array_key_exists("keys", $jwk))
                return JWKSet::createFromKeyData($jwk);
            else
            {
                if(array_is_list($jwk))
                    return JWKSet::createFromKeyData(["keys" => $jwk]);
                else
                {
                    if(!array_key_exists("kty", $jwk))
                        throw new UnauthorizedException("tokenKeyInvalid", "JWK is missing a required \"kty\" claim");

                    $jwk = new JWK($jwk);
                }
            }
        }

        if($jwk instanceof JWK)
        {
            $jwk = new JWKSet([$jwk]);
        }

        return $jwk;
    }
}