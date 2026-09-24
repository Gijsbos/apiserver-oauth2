<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateProvider;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateProviderInterface;
use gijsbos\ApiServer\OAuth2\Certificate\CertificateSet;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerifier;
use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\UnauthorizedException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;

/**
 * AccessTokenVerifierTest
 *  Exercises AccessTokenVerifier directly (no HTTP), including the policy options
 *  (issuer, audience, algorithms) that the shared test server does not configure.
 */
class AccessTokenVerifierTest extends TestCase
{
    private function policy(mixed ...$policyArgs) : AccessTokenVerificationPolicy
    {
        $policyArgs += ["keys" => ["keys" => [JwtFactory::publicKey()]]];

        return new AccessTokenVerificationPolicy(...$policyArgs);
    }

    private function verifier() : AccessTokenVerifier
    {
        return new AccessTokenVerifier(new CertificateProvider());
    }

    private function verify(string $accessToken) : array
    {
        return $this->verifier()->verify($this->policy(), $accessToken);
    }

    private function assertRejected(string $error, callable $verify) : void
    {
        try
        {
            $verify();
        }
        catch(UnauthorizedException $ex)
        {
            $this->assertEquals($error, $ex->getError(), $ex->getMessage());
            return;
        }

        $this->fail("Expected UnauthorizedException \"$error\"");
    }

    // ---------------------------------------------------------------------
    // verify()
    // ---------------------------------------------------------------------

    public function testVerifyReturnsThePayload() : void
    {
        $payload = $this->verify(JwtFactory::mint(["scp" => "a b", "custom" => ["nested" => true]]));

        $this->assertEquals("test-user", $payload["sub"]);
        $this->assertEquals("a b", $payload["scp"]);
        $this->assertEquals(["nested" => true], $payload["custom"]);
    }

    public function testMalformedTokensAreRejectedAsInvalid() : void
    {
        foreach(["", "abc", "a.b", "a.b.c.d.e"] as $token)
            $this->assertRejected("tokenInvalid", fn() => $this->verify($token));
    }

    public function testTamperedPayloadIsRejected() : void
    {
        $token = JwtFactory::withReplacedPayload(JwtFactory::mint(["scp" => "a"]), ["scp" => "admin"]);

        $this->assertRejected("tokenInvalid", fn() => $this->verify($token));
    }

    public function testForeignKeySignatureIsRejected() : void
    {
        $token = JwtFactory::mint([], null, null, JwtFactory::foreignKey());

        $this->assertRejected("tokenInvalid", fn() => $this->verify($token));
    }

    public function testNonObjectPayloadIsRejected() : void
    {
        foreach(['"a string"', 'not json', '5', 'null', 'true'] as $payload)
            $this->assertRejected("tokenPayloadInvalid", fn() => $this->verify(JwtFactory::mint($payload)));
    }

    public function testExpiredTokenIsRejected() : void
    {
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verify(JwtFactory::mint(["exp" => time() - 1])));
    }

    public function testExpMustBePresent() : void
    {
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verify(JwtFactory::mint(["exp" => null])));
    }

    public function testNotBeforeInTheFutureIsRejected() : void
    {
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verify(JwtFactory::mint(["nbf" => time() + 600])));
    }

    public function testNotBeforeInThePastIsAccepted() : void
    {
        $this->assertArrayHasKey("nbf", $this->verify(JwtFactory::mint(["nbf" => time() - 600])));
    }

    // ---------------------------------------------------------------------
    // Injected clock
    // ---------------------------------------------------------------------

    private function clockAt(string $when) : ClockInterface
    {
        return new class($when) implements ClockInterface
        {
            public function __construct(private string $when)
            { }

            public function now() : DateTimeImmutable
            {
                return new DateTimeImmutable($this->when);
            }
        };
    }

    private function verifierWithClock(ClockInterface $clock) : AccessTokenVerifier
    {
        return new AccessTokenVerifier(new CertificateProvider(), $clock);
    }

    public function testInjectedClockDecidesWhenATokenExpires() : void
    {
        $token = JwtFactory::mint(["exp" => time() + 3600]);

        $this->assertEquals("test-user", $this->verifierWithClock($this->clockAt("+30 minutes"))->verify($this->policy(), $token)["sub"]);
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifierWithClock($this->clockAt("+2 hours"))->verify($this->policy(), $token));
    }

    public function testInjectedClockDecidesWhenATokenBecomesValid() : void
    {
        $token = JwtFactory::mint(["nbf" => time() + 3600, "exp" => time() + 7200 * 2]);

        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifierWithClock($this->clockAt("now"))->verify($this->policy(), $token));
        $this->assertEquals("test-user", $this->verifierWithClock($this->clockAt("+2 hours"))->verify($this->policy(), $token)["sub"]);
    }

    // ---------------------------------------------------------------------
    // Injected certificate provider
    // ---------------------------------------------------------------------

    private function providerFor(array $keys, int &$calls = 0) : CertificateProviderInterface
    {
        return new class($keys, $calls) implements CertificateProviderInterface
        {
            public function __construct(private array $keys, private int &$calls)
            { }

            public function provide(AccessTokenVerificationPolicy $accessTokenVerificationPolicy) : CertificateSet
            {
                $this->calls++;

                return new CertificateSet($this->keys);
            }
        };
    }

    public function testKeysComeFromTheInjectedProviderNotThePolicy() : void
    {
        // The policy holds a key that cannot verify the token; only the provider's key can
        $policy = new AccessTokenVerificationPolicy(keys: ["keys" => [JwtFactory::foreignKey()->toPublic()->all()]]);
        $calls = 0;
        $verifier = new AccessTokenVerifier($this->providerFor([JwtFactory::publicKey()], $calls));

        $this->assertEquals("test-user", $verifier->verify($policy, JwtFactory::mint())["sub"]);
        $this->assertEquals(1, $calls);
    }

    public function testEmptyProvidedSetRejectsTokensWithKid() : void
    {
        $policy = new AccessTokenVerificationPolicy(keys: ["keys" => []]);
        $verifier = new AccessTokenVerifier($this->providerFor([]));

        $this->assertRejected("tokenKeyNotFound", fn() => $verifier->verify($policy, JwtFactory::mint()));
    }

    public function testEmptyProvidedSetRejectsTokensWithoutKid() : void
    {
        $policy = new AccessTokenVerificationPolicy(keys: ["keys" => []]);
        $verifier = new AccessTokenVerifier($this->providerFor([]));

        $this->assertRejected("tokenKeyInvalid", fn() => $verifier->verify($policy, JwtFactory::mint([], ["alg" => "RS256"])));
    }

    // ---------------------------------------------------------------------
    // kid handling
    // ---------------------------------------------------------------------

    public function testKidRequiredRejectsTokensWithoutKid() : void
    {
        $token = JwtFactory::mint([], ["alg" => "RS256"]);

        $this->assertRejected("tokenHeaderInvalid", fn() => $this->verifier()->verify($this->policy(kidRequired: true), $token));
    }

    public function testKidOptionalFallsBackToTheWholeKeySet() : void
    {
        $token = JwtFactory::mint([], ["alg" => "RS256"]);

        $this->assertEquals("test-user", $this->verifier()->verify($this->policy(kidRequired: false), $token)["sub"]);
    }

    public function testUnknownKidIsRejected() : void
    {
        $token = JwtFactory::mint([], ["alg" => "RS256", "kid" => "unknown"]);

        $this->assertRejected("tokenKeyNotFound", fn() => $this->verify($token));
    }

    public function testKidSelectsTheMatchingKeyFromAKeySet() : void
    {
        $decoy = array_merge(JwtFactory::foreignKey()->toPublic()->all(), ["kid" => "decoy"]);
        $policy = $this->policy(keys: ["keys" => [$decoy, JwtFactory::publicKey()]]);

        $this->assertEquals("test-user", $this->verifier()->verify($policy, JwtFactory::mint())["sub"]);
    }

    public function testInvalidKeyInKeySetIsRejectedWhenTokenHasNoKid() : void
    {
        $policy = $this->policy(keys: ["keys" => [["foo" => "bar"]]]);

        $this->assertRejected("tokenKeyInvalid", fn() => $this->verifier()->verify($policy, JwtFactory::mint([], ["alg" => "RS256"])));
    }

    // ---------------------------------------------------------------------
    // Algorithms
    // ---------------------------------------------------------------------

    public function testUnsignedTokenIsRejected() : void
    {
        $b64 = fn(string $json) => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $token = $b64('{"alg":"none"}') . "." . $b64(json_encode(JwtFactory::claims())) . ".";

        $this->assertRejected("tokenHeaderInvalid", fn() => $this->verify($token));
    }

    public function testAlgorithmOutsideThePolicyIsRejected() : void
    {
        $unpinnedKey = new JWK(array_diff_key(EXAMPLE_KEY_SET->all(), ["alg" => true])); // EXAMPLE_KEY_SET is pinned to RS256, which would refuse to sign RS384
        $token = JwtFactory::mint([], ["alg" => "RS384", "kid" => JwtFactory::kid()], new RS384(), $unpinnedKey);

        $this->assertRejected("tokenHeaderInvalid", fn() => $this->verifier()->verify($this->policy(allowedAlgorithms: [new RS256()]), $token));
    }

    public function testKeyPinnedToAnotherAlgorithmIsRejected() : void
    {
        // The published key carries "alg": "RS256", so an RS384 signature must not verify even when the policy allows RS384
        $unpinnedKey = new JWK(array_diff_key(EXAMPLE_KEY_SET->all(), ["alg" => true]));
        $token = JwtFactory::mint([], ["alg" => "RS384", "kid" => JwtFactory::kid()], new RS384(), $unpinnedKey);

        $this->assertRejected("tokenInvalid", fn() => $this->verifier()->verify($this->policy(allowedAlgorithms: [new RS256(), new RS384()]), $token));
    }

    // ---------------------------------------------------------------------
    // iss / aud
    // ---------------------------------------------------------------------

    public function testIssuerIsNotCheckedWhenNoIssuerUriIsConfigured() : void
    {
        $this->assertEquals("https://anything", $this->verify(JwtFactory::mint(["iss" => "https://anything"]))["iss"]);
    }

    public function testIssuerMustMatchWhenConfigured() : void
    {
        $policy = $this->policy(issuerUri: "https://issuer.example.com");

        $this->assertEquals("https://issuer.example.com", $this->verifier()->verify($policy, JwtFactory::mint(["iss" => "https://issuer.example.com"]))["iss"]);
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifier()->verify($policy, JwtFactory::mint(["iss" => "https://evil.example.com"])));
    }

    public function testIssuerBecomesMandatoryWhenConfigured() : void
    {
        $policy = $this->policy(issuerUri: "https://issuer.example.com");

        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifier()->verify($policy, JwtFactory::mint(["iss" => null])));
    }

    public function testAudienceIsNotCheckedWhenNotConfigured() : void
    {
        $this->assertEquals("whatever", $this->verify(JwtFactory::mint(["aud" => "whatever"]))["aud"]);
    }

    public function testAudienceMustMatchWhenConfigured() : void
    {
        $policy = $this->policy(audience: "api");

        $this->assertEquals("api", $this->verifier()->verify($policy, JwtFactory::mint(["aud" => "api"]))["aud"]);
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifier()->verify($policy, JwtFactory::mint(["aud" => "other"])));
    }

    public function testAudienceMayBeAnArrayContainingTheConfiguredAudience() : void
    {
        $policy = $this->policy(audience: "api");

        $this->assertEquals(["other", "api"], $this->verifier()->verify($policy, JwtFactory::mint(["aud" => ["other", "api"]]))["aud"]);
    }

    public function testAudienceBecomesMandatoryWhenConfigured() : void
    {
        $this->assertRejected("tokenPayloadInvalid", fn() => $this->verifier()->verify($this->policy(audience: "api"), JwtFactory::mint(["aud" => null])));
    }

    // ---------------------------------------------------------------------
    // verifyHasAuthority()
    // ---------------------------------------------------------------------

    public function testVerifyHasAuthorityReturnsWhenAnyPermissionMatches() : void
    {
        AccessTokenVerifier::verifyHasAuthority(["a", "b", "c"], ["x", "c"]);

        $this->addToAssertionCount(1);
    }

    public function testVerifyHasAuthorityThrowsForbiddenWithDefaultScopeError() : void
    {
        try
        {
            AccessTokenVerifier::verifyHasAuthority(["a"], ["b"]);
        }
        catch(ForbiddenException $ex)
        {
            $this->assertEquals("insufficientScope", $ex->getError());
            return;
        }

        $this->fail("Expected ForbiddenException");
    }

    public function testVerifyHasAuthorityUsesTheGivenError() : void
    {
        try
        {
            AccessTokenVerifier::verifyHasAuthority(["a"], ["b"], "custom", "custom description");
        }
        catch(ForbiddenException $ex)
        {
            $this->assertEquals("custom", $ex->getError());
            $this->assertStringContainsString("custom description", $ex->getMessage());
            return;
        }

        $this->fail("Expected ForbiddenException");
    }

    public function testVerifyHasAuthorityComparesStrictly() : void
    {
        // Loose comparison would let true == "admin" and 0 == "0" through
        foreach([[true], [1], [0], [null], [["admin"]]] as $permissions)
        {
            try
            {
                AccessTokenVerifier::verifyHasAuthority($permissions, ["admin", "0", "1"]);
                $this->fail("Permissions " . json_encode($permissions) . " were accepted");
            }
            catch(ForbiddenException $ex)
            {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testVerifyHasAuthorityNeverMatchesEmptyStrings() : void
    {
        $this->expectException(ForbiddenException::class);

        AccessTokenVerifier::verifyHasAuthority(["x", "", "y"], ["a", ""]);
    }

    #[DataProvider('emptyPermissionSets')]
    public function testVerifyHasAuthorityDeniesWhenNothingIsGranted(array $permissions) : void
    {
        $this->expectException(ForbiddenException::class);

        AccessTokenVerifier::verifyHasAuthority($permissions, ["admin"]);
    }

    public static function emptyPermissionSets() : array
    {
        return [
            "no permissions" => [[]],
            "unrelated permissions" => [["user", "guest"]],
        ];
    }
}
