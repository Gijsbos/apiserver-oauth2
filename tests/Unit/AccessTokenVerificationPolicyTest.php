<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;

/**
 * AccessTokenVerificationPolicyTest
 */
class AccessTokenVerificationPolicyTest extends TestCase
{
    public function testKeySourceIsNotRequiredAtConstruction() : void
    {
        // The "at least one key source" check lives in CertificateProvider::provide()
        $this->assertInstanceOf(AccessTokenVerificationPolicy::class, new AccessTokenVerificationPolicy());
    }

    public function testEachKeySourceIsSufficientOnItsOwn() : void
    {
        $this->assertInstanceOf(AccessTokenVerificationPolicy::class, new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey()));
        $this->assertInstanceOf(AccessTokenVerificationPolicy::class, new AccessTokenVerificationPolicy(keysUri: "https://issuer.example.com/keys"));
        $this->assertInstanceOf(AccessTokenVerificationPolicy::class, new AccessTokenVerificationPolicy(issuerUri: "https://issuer.example.com"));
    }

    public function testDefaults() : void
    {
        $policy = new AccessTokenVerificationPolicy(issuerUri: "https://issuer.example.com");

        $this->assertNull($policy->keysUri);
        $this->assertNull($policy->keys);
        $this->assertNull($policy->audience);
        $this->assertFalse($policy->kidRequired);
        $this->assertCount(1, $policy->allowedAlgorithms);
        $this->assertInstanceOf(RS256::class, $policy->allowedAlgorithms[0]);
    }

    public function testAllowedAlgorithmsMustBeSignatureAlgorithmInstances() : void
    {
        $this->expectException(InvalidArgumentException::class);

        new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey(), allowedAlgorithms: ["RS256"]);
    }

    public function testAllowedAlgorithmsMustNotBeEmpty() : void
    {
        $this->expectException(InvalidArgumentException::class);

        new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey(), allowedAlgorithms: []);
    }

    public function testMultipleAlgorithmsAreAccepted() : void
    {
        $policy = new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey(), allowedAlgorithms: [new RS256(), new RS384()]);

        $this->assertCount(2, $policy->allowedAlgorithms);
    }

    public function testPolicyIsImmutable() : void
    {
        $policy = new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey());

        $this->expectException(Error::class);

        $policy->audience = "changed";
    }
}
