<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateSet;
use gijsbos\Http\Exceptions\InternalServerErrorException;
use gijsbos\Http\Exceptions\UnauthorizedException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * CertificateSetTest
 */
class CertificateSetTest extends TestCase
{
    private function assertThrowsError(string $exceptionClass, string $error, callable $call) : void
    {
        try
        {
            $call();
        }
        catch(InternalServerErrorException | UnauthorizedException $ex)
        {
            $this->assertInstanceOf($exceptionClass, $ex);
            $this->assertEquals($error, $ex->getError());
            return;
        }

        $this->fail("Expected $exceptionClass \"$error\"");
    }

    // ---------------------------------------------------------------------
    // createFromArray()
    // ---------------------------------------------------------------------

    public function testCreatesFromAJwksArray() : void
    {
        $set = CertificateSet::createFromArray(["keys" => [JwtFactory::publicKey()]]);

        $this->assertTrue($set->hasKeys());
        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    public function testCreatesAnEmptySet() : void
    {
        $this->assertFalse(CertificateSet::createFromArray(["keys" => []])->hasKeys());
    }

    public function testWrapsASingleJwkIntoASet() : void
    {
        $set = CertificateSet::createFromArray(JwtFactory::publicKey());

        $this->assertCount(1, $set->toKeysData()["keys"]);
        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    public function testRejectsDataWithoutAKeysArray() : void
    {
        foreach([[JwtFactory::publicKey()], [], ["keys" => "not an array"]] as $data)
            $this->assertThrowsError(InternalServerErrorException::class, "malformedCertificateSet", fn() => CertificateSet::createFromArray($data));
    }

    public function testArrayIsCertificateSet() : void
    {
        $this->assertTrue(CertificateSet::arrayIsCertificateSet(["keys" => []]));
        $this->assertFalse(CertificateSet::arrayIsCertificateSet(JwtFactory::publicKey()));
        $this->assertFalse(CertificateSet::arrayIsCertificateSet(["keys" => null]));
    }

    // ---------------------------------------------------------------------
    // kid lookup / accessors
    // ---------------------------------------------------------------------

    public function testGetKidReturnsTheMatchingKey() : void
    {
        $other = array_merge(JwtFactory::publicKey(), ["kid" => "second"]);
        $set = new CertificateSet([JwtFactory::publicKey(), $other]);

        $this->assertEquals($other, $set->getKid("second"));
        $this->assertEquals(JwtFactory::publicKey(), $set->getKid(JwtFactory::kid()));
    }

    public function testGetKidReturnsNullForUnknownKid() : void
    {
        $set = new CertificateSet([JwtFactory::publicKey()]);

        $this->assertNull($set->getKid("unknown"));
        $this->assertFalse($set->hasKid("unknown"));
    }

    public function testGetKidSkipsMalformedEntries() : void
    {
        // Remote key sets are untrusted input: a non-array entry or non-string kid must not throw
        $set = new CertificateSet(["not a key", ["kid" => ["array"]], ["kid" => 7], JwtFactory::publicKey()]);

        $this->assertNull($set->getKid("7"));
        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    public function testToKeysDataWrapsTheKeys() : void
    {
        $this->assertEquals(["keys" => [JwtFactory::publicKey()]], (new CertificateSet([JwtFactory::publicKey()]))->toKeysData());
    }

    public function testToJWKSet() : void
    {
        $jwkSet = (new CertificateSet([JwtFactory::publicKey()]))->toJWKSet();

        $this->assertCount(1, $jwkSet);
        $this->assertTrue($jwkSet->has(JwtFactory::kid()));
    }

    // ---------------------------------------------------------------------
    // addCertificateData()
    // ---------------------------------------------------------------------

    public function testAddCertificateDataAppendsAKey() : void
    {
        $set = new CertificateSet([]);
        $set->addCertificateData(JwtFactory::publicKey());

        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    public function testAddCertificateDataAppendsEveryKeyOfASet() : void
    {
        $other = array_merge(JwtFactory::publicKey(), ["kid" => "second"]);
        $set = new CertificateSet([]);
        $set->addCertificateData(["keys" => [JwtFactory::publicKey(), $other]]);

        $this->assertTrue($set->hasKid(JwtFactory::kid()));
        $this->assertTrue($set->hasKid("second"));
        $this->assertCount(2, $set->toKeysData()["keys"]);
    }

    public function testAddCertificateDataRequiresAKid() : void
    {
        $withoutKid = array_diff_key(JwtFactory::publicKey(), ["kid" => true]);

        $this->assertThrowsError(InternalServerErrorException::class, "malformedCertificate", fn() => (new CertificateSet([]))->addCertificateData($withoutKid));
    }

    public function testAddCertificateDataAddsNothingWhenAnyKeyInTheSetLacksAKid() : void
    {
        $withoutKid = array_diff_key(JwtFactory::publicKey(), ["kid" => true]);
        $set = new CertificateSet([]);

        $this->assertThrowsError(InternalServerErrorException::class, "malformedCertificate", fn() => $set->addCertificateData(["keys" => [JwtFactory::publicKey(), $withoutKid]]));
        $this->assertFalse($set->hasKeys());
    }

    // ---------------------------------------------------------------------
    // convertToJWKSet()
    // ---------------------------------------------------------------------

    public function testConvertsASingleJwkArray() : void
    {
        $set = CertificateSet::convertToJWKSet(JwtFactory::publicKey());

        $this->assertInstanceOf(JWKSet::class, $set);
        $this->assertCount(1, $set);
        $this->assertTrue($set->has(JwtFactory::kid()));
    }

    public function testConvertsAJwksArray() : void
    {
        $set = CertificateSet::convertToJWKSet(["keys" => [JwtFactory::publicKey()]]);

        $this->assertCount(1, $set);
        $this->assertTrue($set->has(JwtFactory::kid()));
    }

    public function testConvertsAListOfJwks() : void
    {
        $other = array_merge(JwtFactory::publicKey(), ["kid" => "second"]);
        $set = CertificateSet::convertToJWKSet([JwtFactory::publicKey(), $other]);

        $this->assertCount(2, $set);
        $this->assertTrue($set->has("second"));
    }

    public function testConvertsAJsonString() : void
    {
        $this->assertCount(1, CertificateSet::convertToJWKSet(json_encode(["keys" => [JwtFactory::publicKey()]])));
        $this->assertCount(1, CertificateSet::convertToJWKSet(json_encode(JwtFactory::publicKey())));
    }

    public function testConvertsAJwkObject() : void
    {
        $this->assertCount(1, CertificateSet::convertToJWKSet(new JWK(JwtFactory::publicKey())));
    }

    public function testPassesAJwkSetThrough() : void
    {
        $set = new JWKSet([new JWK(JwtFactory::publicKey())]);

        $this->assertSame($set, CertificateSet::convertToJWKSet($set));
    }

    public function testRejectsAnAssociativeArrayWithoutKty() : void
    {
        $this->assertThrowsError(UnauthorizedException::class, "tokenKeyInvalid", fn() => CertificateSet::convertToJWKSet(["foo" => "bar"]));
    }
}
