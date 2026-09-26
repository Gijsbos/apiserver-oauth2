<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateProvider;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateSet;
use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;
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
    protected function setUp() : void
    {
        CertificateProvider::clearCache();
    }

    protected function tearDown() : void
    {
        CertificateProvider::$REFRESH_COOLDOWN_SECONDS = 60;
        CertificateProvider::$FAILURE_CACHE_TTL_SECONDS = 30;
        CertificateProvider::clearCache();
    }

    /**
     * A provider that serves $responses (uri => decoded JSON) instead of using the network, and records every fetched uri
     */
    private function offlineProvider(array &$responses, array &$fetched) : CertificateProvider
    {
        return new class($responses, $fetched) extends CertificateProvider
        {
            public function __construct(private array &$responses, private array &$fetched)
            { }

            protected function fetchJson(string $uri) : null|array
            {
                $this->fetched[] = $uri;

                return $this->responses[$uri] ?? null;
            }
        };
    }

    private function assertThrowsUnauthorized(string $error, callable $call) : void
    {
        try
        {
            $call();
        }
        catch(UnauthorizedException $ex)
        {
            $this->assertEquals($error, $ex->getError(), $ex->getMessage());
            return;
        }

        $this->fail("Expected UnauthorizedException \"$error\"");
    }

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
        return (new CertificateProvider())->provide(new OAuth2VerificationPolicy(...$policyArgs));
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

    public function testPolicyKeysMayBeASingleJwk() : void
    {
        $this->assertTrue($this->provide(keys: JwtFactory::publicKey())->hasKid(JwtFactory::kid()));
    }

    public function testPolicyKeysMustNotBeABareListOfJwks() : void
    {
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

    public function testKeysUriAndIssuerUriOfTheSameValueDoNotShareACacheEntry() : void
    {
        $this->assertTrue($this->provide(keysUri: $this->jwksUri())->hasKid(JwtFactory::kid()));

        // The JWKS URL is no issuer (it has no discovery document), so the keys cached for it as keysUri must not be served
        $this->assertProvideFails(UnauthorizedException::class, "tokenIssuerUnavailable", issuerUri: $this->jwksUri());
    }

    // ---------------------------------------------------------------------
    // Caching, refresh and failures (offline)
    // ---------------------------------------------------------------------

    public function testFetchedKeysAreServedFromTheCache() : void
    {
        $responses = ["https://idp/keys" => ["keys" => [JwtFactory::publicKey()]]];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $provider->provide($policy);
        $this->assertTrue($provider->provide($policy)->hasKid(JwtFactory::kid()));
        $this->assertCount(1, $fetched);
    }

    public function testRefreshWithinTheCooldownServesTheCachedKeys() : void
    {
        $responses = ["https://idp/keys" => ["keys" => []]];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $provider->provide($policy);
        $responses["https://idp/keys"] = ["keys" => [JwtFactory::publicKey()]];

        // Every token with a made-up kid asks for a refresh; within the cooldown none of them may reach the issuer
        for($i = 0; $i < 5; $i++)
            $this->assertFalse($provider->provide($policy, true)->hasKid(JwtFactory::kid()));

        $this->assertCount(1, $fetched);
    }

    public function testRefreshAfterTheCooldownRefetches() : void
    {
        CertificateProvider::$REFRESH_COOLDOWN_SECONDS = 0;

        $responses = ["https://idp/keys" => ["keys" => []]];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $provider->provide($policy);
        $responses["https://idp/keys"] = ["keys" => [JwtFactory::publicKey()]];

        $this->assertFalse($provider->provide($policy)->hasKid(JwtFactory::kid()), "Without refresh the cached set is served");
        $this->assertTrue($provider->provide($policy, true)->hasKid(JwtFactory::kid()));
        $this->assertTrue($provider->provide($policy)->hasKid(JwtFactory::kid()), "The refreshed set replaces the cached one");
        $this->assertCount(2, $fetched);
    }

    public function testFailedRefreshKeepsServingTheCachedKeys() : void
    {
        CertificateProvider::$REFRESH_COOLDOWN_SECONDS = 0;

        $responses = ["https://idp/keys" => ["keys" => [JwtFactory::publicKey()]]];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $provider->provide($policy);
        unset($responses["https://idp/keys"]);

        $this->assertTrue($provider->provide($policy, true)->hasKid(JwtFactory::kid()));
    }

    public function testFailedFetchIsRememberedWithoutContactingTheIssuerAgain() : void
    {
        $responses = [];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $this->assertThrowsUnauthorized("tokenKeysUnavailable", fn() => $provider->provide($policy));
        $this->assertThrowsUnauthorized("tokenKeysUnavailable", fn() => $provider->provide($policy, true));
        $this->assertCount(1, $fetched);
    }

    public function testFailedFetchIsRetriedOnceTheFailureExpires() : void
    {
        CertificateProvider::$FAILURE_CACHE_TTL_SECONDS = 0;

        $responses = [];
        $fetched = [];
        $provider = $this->offlineProvider($responses, $fetched);
        $policy = new OAuth2VerificationPolicy(keysUri: "https://idp/keys");

        $this->assertThrowsUnauthorized("tokenKeysUnavailable", fn() => $provider->provide($policy));
        $responses["https://idp/keys"] = ["keys" => [JwtFactory::publicKey()]];

        $this->assertTrue($provider->provide($policy)->hasKid(JwtFactory::kid()));
        $this->assertCount(2, $fetched);
    }

    // ---------------------------------------------------------------------
    // Discovery document validation (offline)
    // ---------------------------------------------------------------------

    private function discover(string $issuerUri, array $configuration) : CertificateSet
    {
        $responses = [
            "https://idp" . CertificateProvider::WELL_KNOWN_OPEN_ID_PATH => $configuration,
            "https://idp/keys" => ["keys" => [JwtFactory::publicKey()]],
        ];
        $fetched = [];

        return $this->offlineProvider($responses, $fetched)->provide(new OAuth2VerificationPolicy(issuerUri: $issuerUri));
    }

    public function testDiscoveryAcceptsTheConfigurationOfTheIssuer() : void
    {
        $this->assertTrue($this->discover("https://idp", ["issuer" => "https://idp", "jwks_uri" => "https://idp/keys"])->hasKid(JwtFactory::kid()));
        $this->assertTrue($this->discover("https://idp/", ["issuer" => "https://idp", "jwks_uri" => "https://idp/keys"])->hasKid(JwtFactory::kid()));
        $this->assertTrue($this->discover("https://idp", ["issuer" => "https://idp/", "jwks_uri" => "https://idp/keys"])->hasKid(JwtFactory::kid()));
    }

    public function testDiscoveryRejectsTheConfigurationOfAnotherIssuer() : void
    {
        foreach([["issuer" => "https://evil.example.com"], ["issuer" => "https://idp.evil"], ["issuer" => ["https://idp"]], []] as $issuer)
        {
            CertificateProvider::clearCache();

            $this->assertThrowsUnauthorized("tokenIssuerUnavailable", fn() => $this->discover("https://idp", $issuer + ["jwks_uri" => "https://idp/keys"]));
        }
    }

    public function testDiscoveryRequiresAJwksUri() : void
    {
        $this->assertThrowsUnauthorized("tokenIssuerUnavailable", fn() => $this->discover("https://idp", ["issuer" => "https://idp"]));
    }

    // ---------------------------------------------------------------------
    // End to end with a remote key source
    // ---------------------------------------------------------------------

    public function testVerifierAcceptsTokensSignedByKeysFetchedFromKeysUri() : void
    {
        $policy = new OAuth2VerificationPolicy(keysUri: $this->jwksUri(), kidRequired: true);
        $verifier = new AccessTokenVerifier(new CertificateProvider());

        $this->assertEquals("test-user", $verifier->verify($policy, JwtFactory::mint())->getSub());
    }

    public function testVerifierValidatesIssuerFromDiscoveryConfiguration() : void
    {
        $policy = new OAuth2VerificationPolicy(issuerUri: $this->issuerUri());
        $verifier = new AccessTokenVerifier(new CertificateProvider());

        $this->assertEquals("test-user", $verifier->verify($policy, JwtFactory::mint(["iss" => $this->issuerUri()]))->getSub());

        $this->expectException(UnauthorizedException::class);

        $verifier->verify($policy, JwtFactory::mint(["iss" => "https://evil.example.com"]));
    }
}
