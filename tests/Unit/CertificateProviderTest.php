<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateProvider;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateSet;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;
use gijsbos\ApiServer\Parsers\RouteParser;
use gijsbos\Http\Exceptions\InternalServerErrorException;
use gijsbos\Http\Exceptions\UnauthorizedException;

/**
 * CertificateProviderTest
 *  The keysUri / issuerUri tests use the /test/idp/* routes of TestController,
 *  served by the same running server as the other route tests.
 */
class CertificateProviderTest extends TestCase
{
    private function jwksUri() : string
    {
        return RouteParser::getRoute(['TestController', 'jwks'])->getFullPath(false);
    }

    private function issuerUri() : string
    {
        return rtrim(env("BASE_URL"), "/") . "/test/idp";
    }

    private function provide(mixed ...$policyArgs) : CertificateSet
    {
        return (new CertificateProvider())->provide(new AccessTokenVerificationPolicy(...$policyArgs));
    }

    private function assertProvideFails(string $exceptionClass, string $error, mixed ...$policyArgs) : void
    {
        try
        {
            $this->provide(...$policyArgs);
        }
        catch(UnauthorizedException | InternalServerErrorException $ex)
        {
            $this->assertInstanceOf($exceptionClass, $ex);
            $this->assertEquals($error, $ex->getError());
            return;
        }

        $this->fail("Expected $exceptionClass \"$error\"");
    }

    // ---------------------------------------------------------------------
    // Key source
    // ---------------------------------------------------------------------

    public function testRequiresAtLeastOneKeySource() : void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->provide();
    }

    public function testAudienceAloneIsNotAKeySource() : void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->provide(audience: "api");
    }

    // ---------------------------------------------------------------------
    // keys
    // ---------------------------------------------------------------------

    public function testProvidesPolicyKeysWithoutUsingTheNetwork() : void
    {
        $set = $this->provide(keys: ["keys" => [JwtFactory::publicKey()]]);

        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    public function testPolicyKeysMustBeAJwksArray() : void
    {
        $this->assertProvideFails(InternalServerErrorException::class, "malformedCertificateSet", keys: JwtFactory::publicKey());
        $this->assertProvideFails(InternalServerErrorException::class, "malformedCertificateSet", keys: [JwtFactory::publicKey()]);
    }

    public function testKeysTakePrecedenceOverKeysUri() : void
    {
        $set = $this->provide(
            keys: ["keys" => [JwtFactory::publicKey()]],
            keysUri: "http://invalid.invalid/never-called",
            issuerUri: "http://invalid.invalid/never-called",
        );

        $this->assertTrue($set->hasKid(JwtFactory::kid()));
    }

    // ---------------------------------------------------------------------
    // keysUri / issuerUri
    // ---------------------------------------------------------------------

    public function testProvidesKeysFromKeysUri() : void
    {
        $this->assertTrue($this->provide(keysUri: $this->jwksUri())->hasKid(JwtFactory::kid()));
    }

    public function testProvidesKeysViaOpenIdDiscovery() : void
    {
        $this->assertTrue($this->provide(issuerUri: $this->issuerUri())->hasKid(JwtFactory::kid()));
    }

    public function testOpenIdDiscoveryToleratesATrailingSlashOnTheIssuerUri() : void
    {
        $this->assertTrue($this->provide(issuerUri: $this->issuerUri() . "/")->hasKid(JwtFactory::kid()));
    }

    public function testUnreachableKeysUriIsReportedAsUnavailable() : void
    {
        $this->assertProvideFails(UnauthorizedException::class, "tokenKeysUnavailable", keysUri: $this->jwksUri() . "-missing");
    }

    public function testUnreachableDiscoveryDocumentIsReportedAsUnavailable() : void
    {
        $this->assertProvideFails(UnauthorizedException::class, "tokenIssuerUnavailable", issuerUri: $this->issuerUri() . "-missing");
    }

    // ---------------------------------------------------------------------
    // End to end with a remote key source
    // ---------------------------------------------------------------------

    public function testVerifierAcceptsTokensSignedByKeysFetchedFromKeysUri() : void
    {
        $policy = new AccessTokenVerificationPolicy(keysUri: $this->jwksUri(), kidRequired: true);
        $verifier = new AccessTokenVerifier(new CertificateProvider());

        $this->assertEquals("test-user", $verifier->verify($policy, JwtFactory::mint())["sub"]);
    }

    public function testVerifierValidatesIssuerFromDiscoveryConfiguration() : void
    {
        $policy = new AccessTokenVerificationPolicy(issuerUri: $this->issuerUri());
        $verifier = new AccessTokenVerifier(new CertificateProvider());

        $this->assertEquals("test-user", $verifier->verify($policy, JwtFactory::mint(["iss" => $this->issuerUri()]))["sub"]);

        $this->expectException(UnauthorizedException::class);

        $verifier->verify($policy, JwtFactory::mint(["iss" => "https://evil.example.com"]));
    }
}
