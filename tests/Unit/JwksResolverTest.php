<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;
use gijsbos\ApiServer\OAuth2\Components\JwksResolver;
use gijsbos\ApiServer\Parsers\RouteParser;
use gijsbos\Http\Exceptions\UnauthorizedException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * JwksResolverTest
 *  The keysUri / issuerUri tests use the /test/idp/* routes of TestController,
 *  served by the same running server as the other route tests.
 */
class JwksResolverTest extends TestCase
{
    private function jwksUri() : string
    {
        return RouteParser::getRoute(['TestController', 'jwks'])->getFullPath(false);
    }

    private function issuerUri() : string
    {
        return rtrim(env("BASE_URL"), "/") . "/test/idp";
    }

    // ---------------------------------------------------------------------
    // convertToJWKSet()
    // ---------------------------------------------------------------------

    public function testConvertsASingleJwkArray() : void
    {
        $set = JwksResolver::convertToJWKSet(JwtFactory::publicKey());

        $this->assertInstanceOf(JWKSet::class, $set);
        $this->assertCount(1, $set);
        $this->assertTrue($set->has(JwtFactory::kid()));
    }

    public function testConvertsAJwksArray() : void
    {
        $set = JwksResolver::convertToJWKSet(["keys" => [JwtFactory::publicKey()]]);

        $this->assertCount(1, $set);
        $this->assertTrue($set->has(JwtFactory::kid()));
    }

    public function testConvertsAListOfJwks() : void
    {
        $other = array_merge(JwtFactory::publicKey(), ["kid" => "second"]);
        $set = JwksResolver::convertToJWKSet([JwtFactory::publicKey(), $other]);

        $this->assertCount(2, $set);
        $this->assertTrue($set->has("second"));
    }

    public function testConvertsAJsonString() : void
    {
        $this->assertCount(1, JwksResolver::convertToJWKSet(json_encode(["keys" => [JwtFactory::publicKey()]])));
        $this->assertCount(1, JwksResolver::convertToJWKSet(json_encode(JwtFactory::publicKey())));
    }

    public function testConvertsAJwkObject() : void
    {
        $this->assertCount(1, JwksResolver::convertToJWKSet(new JWK(JwtFactory::publicKey())));
    }

    public function testPassesAJwkSetThrough() : void
    {
        $set = new JWKSet([new JWK(JwtFactory::publicKey())]);

        $this->assertSame($set, JwksResolver::convertToJWKSet($set));
    }

    public function testRejectsAnAssociativeArrayWithoutKty() : void
    {
        try
        {
            JwksResolver::convertToJWKSet(["foo" => "bar"]);
        }
        catch(UnauthorizedException $ex)
        {
            $this->assertEquals("tokenKeyInvalid", $ex->getError());
            return;
        }

        $this->fail("Expected UnauthorizedException");
    }

    // ---------------------------------------------------------------------
    // getKeys() / getKey()
    // ---------------------------------------------------------------------

    public function testGetKeysFromPolicyKeysDoesNotUseTheNetwork() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey()));

        $this->assertTrue($resolver->getKeys()->has(JwtFactory::kid()));
        $this->assertEquals(JwtFactory::kid(), $resolver->getKey(JwtFactory::kid())->get("kid"));
    }

    public function testGetKeyThrowsForUnknownKid() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(keys: JwtFactory::publicKey()));

        $this->expectException(InvalidArgumentException::class);

        $resolver->getKey("unknown");
    }

    public function testKeysTakePrecedenceOverKeysUri() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(
            keys: JwtFactory::publicKey(),
            keysUri: "http://invalid.invalid/never-called",
        ));

        $this->assertTrue($resolver->getKeys()->has(JwtFactory::kid()));
    }

    public function testGetKeysFromKeysUri() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(keysUri: $this->jwksUri()));

        $this->assertTrue($resolver->getKeys()->has(JwtFactory::kid()));
    }

    public function testGetKeysViaOpenIdDiscovery() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(issuerUri: $this->issuerUri()));

        $this->assertTrue($resolver->getKeys()->has(JwtFactory::kid()));
    }

    public function testOpenIdDiscoveryToleratesATrailingSlashOnTheIssuerUri() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(issuerUri: $this->issuerUri() . "/"));

        $this->assertTrue($resolver->getKeys()->has(JwtFactory::kid()));
    }

    public function testUnreachableKeysUriIsReportedAsUnavailable() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(keysUri: $this->jwksUri() . "-missing"));

        try
        {
            $resolver->getKeys();
        }
        catch(UnauthorizedException $ex)
        {
            $this->assertEquals("tokenKeysUnavailable", $ex->getError());
            return;
        }

        $this->fail("Expected UnauthorizedException");
    }

    public function testUnreachableDiscoveryDocumentIsReportedAsUnavailable() : void
    {
        $resolver = new JwksResolver(new AccessTokenVerificationPolicy(issuerUri: $this->issuerUri() . "-missing"));

        try
        {
            $resolver->getKeys();
        }
        catch(UnauthorizedException $ex)
        {
            $this->assertEquals("tokenIssuerUnavailable", $ex->getError());
            return;
        }

        $this->fail("Expected UnauthorizedException");
    }

    // ---------------------------------------------------------------------
    // End to end with a remote key source
    // ---------------------------------------------------------------------

    public function testVerifierAcceptsTokensSignedByKeysFetchedFromKeysUri() : void
    {
        $verifier = new AccessTokenVerifier(new AccessTokenVerificationPolicy(keysUri: $this->jwksUri(), kidRequired: true));

        $this->assertEquals("test-user", $verifier->verify(JwtFactory::mint())["sub"]);
    }

    public function testVerifierValidatesIssuerFromDiscoveryConfiguration() : void
    {
        $verifier = new AccessTokenVerifier(new AccessTokenVerificationPolicy(issuerUri: $this->issuerUri()));

        $this->assertEquals("test-user", $verifier->verify(JwtFactory::mint(["iss" => $this->issuerUri()]))["sub"]);

        $this->expectException(UnauthorizedException::class);

        $verifier->verify(JwtFactory::mint(["iss" => "https://evil.example.com"]));
    }
}
