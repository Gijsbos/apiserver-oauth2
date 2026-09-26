<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\ValueObjects\JwtPayload;
use gijsbos\ApiServer\OAuth2\ValueObjects\TokenPayload;

/**
 * TokenPayloadTest
 */
class TokenPayloadTest extends TestCase
{
    private static function jwtClaims() : array
    {
        return ["iss" => "https://issuer.example.com", "sub" => "user", "exp" => 2000, "nbf" => 1000, "iat" => 1000, "jti" => "id"];
    }

    // ---------------------------------------------------------------------
    // createFromArray()
    // ---------------------------------------------------------------------

    public function testCreatesFromArraySplittingCommonAndCustomClaims() : void
    {
        $payload = TokenPayload::createFromArray(["sub" => "user", "aud" => ["a", "b"], "scope" => "read write", "roles" => ["admin"], "tenant" => "t1"]);

        $this->assertEquals("user", $payload->getSub());
        $this->assertEquals(["a", "b"], $payload->getAud());
        $this->assertEquals(["read", "write"], $payload->getScope());
        $this->assertEquals(["admin"], $payload->getRoles());
        $this->assertTrue($payload->hasCustomClaim("tenant"));
        $this->assertEquals("t1", $payload->getClaim("tenant"));
        $this->assertFalse($payload->hasCustomClaim("sub"));
    }

    public function testFractionalNumericDatesAreTruncated() : void
    {
        $this->assertSame(1000, TokenPayload::createFromArray(["exp" => 1000.9])->getExp());
    }

    #[DataProvider('malformedClaims')]
    public function testRejectsMalformedCommonClaims(array $payload) : void
    {
        $this->expectException(InvalidArgumentException::class);

        TokenPayload::createFromArray($payload);
    }

    public static function malformedClaims() : array
    {
        return [
            "iss not a string" => [["iss" => 7]],
            "sub not a string" => [["sub" => ["user"]]],
            "exp not a date" => [["exp" => "tomorrow"]],
            "aud with a non-string entry" => [["aud" => ["a", 7]]],
            "scope not a string or list" => [["scope" => 7]],
            "roles with a non-string entry" => [["roles" => ["admin", true]]],
        ];
    }

    // ---------------------------------------------------------------------
    // toArray()
    // ---------------------------------------------------------------------

    public function testToArrayRoundTrips() : void
    {
        $claims = ["sub" => "user", "exp" => 2000, "scope" => "read write", "roles" => ["admin"], "tenant" => "t1"];

        $this->assertEquals($claims, TokenPayload::createFromArray($claims)->toArray());
    }

    public function testToArrayLeavesOutUnsetClaims() : void
    {
        $this->assertEquals(["sub" => "user"], TokenPayload::createFromArray(["sub" => "user"])->toArray());
    }

    public function testToArrayKeepsNumericCustomClaimNames() : void
    {
        $this->assertEquals(["sub" => "user", "42" => "answer"], TokenPayload::createFromArray(["sub" => "user", "42" => "answer"])->toArray());
    }

    public function testCustomClaimsCannotOverrideCommonClaims() : void
    {
        $this->expectException(InvalidArgumentException::class);

        (new TokenPayload(sub: "user"))->addCustomClaim("sub", "admin");
    }

    // ---------------------------------------------------------------------
    // Metadata
    // ---------------------------------------------------------------------

    public function testMetadata() : void
    {
        $payload = new TokenPayload();
        $payload->addMetadata("source", "test");
        $payload->addMetadata("empty", null);

        $this->assertEquals("test", $payload->getMetadata("source"));
        $this->assertTrue($payload->hasMetadata("empty"));
        $this->assertFalse($payload->hasMetadata("missing"));
        $this->assertNull($payload->getMetadata("missing"));
    }

    // ---------------------------------------------------------------------
    // JwtPayload
    // ---------------------------------------------------------------------

    public function testJwtPayloadRequiresTheRegisteredClaims() : void
    {
        foreach(array_keys(self::jwtClaims()) as $claim)
        {
            try
            {
                JwtPayload::createFromArray(array_diff_key(self::jwtClaims(), [$claim => true]));
                $this->fail("JwtPayload without \"$claim\" was accepted");
            }
            catch(InvalidArgumentException $ex)
            {
                $this->assertStringContainsString("\"$claim\"", $ex->getMessage());
            }
        }
    }

    public function testJwtPayloadFromCopiesClaimsAndMetadata() : void
    {
        $tokenPayload = TokenPayload::createFromArray(self::jwtClaims() + ["tenant" => "t1"]);
        $tokenPayload->addMetadata("source", "test");

        $jwtPayload = JwtPayload::from($tokenPayload);

        $this->assertInstanceOf(JwtPayload::class, $jwtPayload);
        $this->assertEquals($tokenPayload->toArray(), $jwtPayload->toArray());
        $this->assertEquals("test", $jwtPayload->getMetadata("source"));
        $this->assertSame($jwtPayload, JwtPayload::from($jwtPayload));
    }

    public function testRequiredClaims() : void
    {
        $this->assertSame([], TokenPayload::getRequiredClaims());
        $this->assertTrue(JwtPayload::isClaimRequired("jti"));
        $this->assertFalse(JwtPayload::isClaimRequired("scope"));
    }
}
