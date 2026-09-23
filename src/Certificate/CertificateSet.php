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
            if(str_equals(@$key["kid"] ?? "", $kid))
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
        $certificates = self::arrayIsCertificateSet($certificateData) ? $certificateData["keys"] : [$certificateData];

        foreach($certificates as $certificate)
            if(!is_array($certificate) || !$this->certificateContainsRequiredKeys($certificate))
                throw new InternalServerErrorException("malformedCertificate", "Certificate data does not contain required keys kid");

        array_push($this->keys, ...$certificates);
    }

    public static function arrayIsCertificateSet(array $data)
    {
        return is_array($data) && array_key_exists("keys", $data) && is_array($data["keys"]);
    }

    public static function createFromArray(array $data)
    {
        if(!self::arrayIsCertificateSet($data))
            throw new InternalServerErrorException("malformedCertificateSet", "Certificate set is malformed");

        return new self($data["keys"]);
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