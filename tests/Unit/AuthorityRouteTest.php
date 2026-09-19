<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\Parsers\RouteParser;
use gijsbos\Http\Http\HTTPRequest;
use gijsbos\Http\Response;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Core\JWK;

/**
 * AuthorityRouteTest
 *  End-to-end tests for #[HasScope] / #[HasRole] and the token verification that
 *  backs them. Requests go to the running server (BASE_URL in .env), which is
 *  configured in index.php with the public EXAMPLE_KEY_SET and kidRequired: true.
 */
class AuthorityRouteTest extends TestCase
{
    private function request(string $method, null|string $token, string $scheme = "Bearer") : Response
    {
        return HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', $method])->getFullPath(false),
            "headers" => $token === null ? [] : ["Authorization" => "$scheme $token"],
        ]);
    }

    private function assertAllowed(Response $response) : void
    {
        $this->assertTrue($response->isSuccessful(), $response->getErrorString());
    }

    private function assertDenied(Response $response, int $status, string $error) : void
    {
        $this->assertFalse($response->isSuccessful());
        $this->assertEquals($status, $response->getStatusCode());
        $this->assertEquals($error, $response->getError(), $response->getErrorString());
    }

    // ---------------------------------------------------------------------
    // Unauthenticated / credential format
    // ---------------------------------------------------------------------

    public function testPublicRouteNeedsNoToken() : void
    {
        $this->assertAllowed($this->request("publicRoute", null));
    }

    public function testPublicRouteIgnoresInvalidToken() : void
    {
        // SecurityContext permits "/**", and the route has no authority attribute, so nothing verifies the token
        $this->assertAllowed($this->request("publicRoute", "not-a-token"));
    }

    #[DataProvider('protectedRoutes')]
    public function testMissingAuthorizationHeaderIsUnauthorized(string $method) : void
    {
        $this->assertDenied($this->request($method, null), 401, "authorizationRequired");
    }

    public static function protectedRoutes() : array
    {
        return [
            "hasScope" => ["hasScope"],
            "hasRole" => ["hasRole"],
            "hasAnyScope" => ["hasAnyScope"],
            "hasScopeArray" => ["hasScopeArray"],
            "hasAnyRole" => ["hasAnyRole"],
            "hasRoleArray" => ["hasRoleArray"],
            "hasScopeAndRole" => ["hasScopeAndRole"],
            "hasNoUsableScope" => ["hasNoUsableScope"],
        ];
    }

    public function testUnknownAuthorizationSchemeIsRejected() : void
    {
        $this->assertDenied($this->request("hasScope", "abc", "Token"), 401, "authorizationHeaderInvalid");
    }

    public function testBasicSchemeIsNotSupported() : void
    {
        // OAuth2Server only wires viaBearer
        $this->assertDenied($this->request("hasScope", base64_encode("user:pass"), "Basic"), 401, "schemeNotSupported");
    }

    public function testBearerSchemeIsCaseInsensitive() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope"]);

        $this->assertAllowed($this->request("hasScope", $token, "bEaReR"));
    }

    // ---------------------------------------------------------------------
    // Token verification
    // ---------------------------------------------------------------------

    public function testNonJwtTokenIsRejected() : void
    {
        $this->assertDenied($this->request("hasScope", "token"), 401, "tokenInvalid");
    }

    public function testExpiredTokenIsRejected() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope", "exp" => time() - 60]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenPayloadInvalid");
    }

    public function testTokenWithoutExpIsRejected() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope", "exp" => null]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenPayloadInvalid");
    }

    public function testTokenNotYetValidIsRejected() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope", "nbf" => time() + 600]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenPayloadInvalid");
    }

    public function testTokenWithoutKidIsRejectedWhenKidRequired() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope"], ["alg" => "RS256"]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenHeaderInvalid");
    }

    public function testTokenWithUnknownKidIsRejected() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope"], ["alg" => "RS256", "kid" => "unknown-kid"]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenKeyNotFound");
    }

    public function testTokenSignedWithForeignKeyIsRejected() : void
    {
        $token = JwtFactory::mint(["scp" => "test-scope"], null, null, JwtFactory::foreignKey());

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenInvalid");
    }

    public function testTokenWithTamperedPayloadIsRejected() : void
    {
        $token = JwtFactory::withReplacedPayload(JwtFactory::mint(["scp" => "other-scope"]), ["scp" => "test-scope"]);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenInvalid");
    }

    public function testUnsupportedAlgorithmIsRejected() : void
    {
        // Classic algorithm confusion: an HS256 token whose kid points at the RSA key
        $hmacKey = new JWK(["kty" => "oct", "k" => rtrim(strtr(base64_encode(str_repeat("k", 32)), '+/', '-_'), '=')]);
        $token = JwtFactory::mint(["scp" => "test-scope"], ["alg" => "HS256", "kid" => JwtFactory::kid()], new HS256(), $hmacKey);

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenHeaderInvalid");
    }

    public function testUnsignedTokenIsRejected() : void
    {
        $b64 = fn(string $json) => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $token = $b64('{"alg":"none","kid":"' . JwtFactory::kid() . '"}') . "." . $b64(json_encode(JwtFactory::claims(["scp" => "test-scope"]))) . ".";

        $this->assertDenied($this->request("hasScope", $token), 401, "tokenHeaderInvalid");
    }

    // ---------------------------------------------------------------------
    // HasScope
    // ---------------------------------------------------------------------

    #[DataProvider('scopeClaimShapes')]
    public function testHasScopeAcceptsSupportedClaimShapes(array $claims) : void
    {
        $this->assertAllowed($this->request("hasScope", JwtFactory::mint($claims)));
    }

    public static function scopeClaimShapes() : array
    {
        return [
            "scp" => [["scp" => "test-scope"]],
            "scopes" => [["scopes" => "test-scope"]],
            "scope" => [["scope" => "test-scope"]],
            "space delimited" => [["scope" => "openid test-scope profile"]],
            "comma delimited" => [["scope" => "openid,test-scope,profile"]],
            "comma and space" => [["scope" => "openid, test-scope"]],
            "double space" => [["scope" => "openid  test-scope"]],
            "array" => [["scp" => ["openid", "test-scope"]]],
            "array in scope claim" => [["scope" => ["test-scope"]]],
        ];
    }

    #[DataProvider('scopeClaimsThatDoNotGrantTestScope')]
    public function testHasScopeDeniesInsufficientScope(array $claims) : void
    {
        $this->assertDenied($this->request("hasScope", JwtFactory::mint($claims)), 403, "insufficientScope");
    }

    public static function scopeClaimsThatDoNotGrantTestScope() : array
    {
        return [
            "no scope claim" => [[]],
            "empty scope" => [["scp" => ""]],
            "other scope" => [["scp" => "other-scope"]],
            "prefix of required" => [["scp" => "test"]],
            "extension of required" => [["scp" => "test-scope-extra"]],
            "case differs" => [["scp" => "TEST-SCOPE"]],
            "empty array" => [["scp" => []]],
            "array without the scope" => [["scp" => ["other-scope"]]],
            "scope is not a string or array" => [["scp" => 5]],
            "array with a non-string entry" => [["scp" => ["test-scope", 5]]],
            "array with a nested array" => [["scp" => [["test-scope"]]]],
            "role claim is not a scope" => [["roles" => "test-scope"]],
        ];
    }

    public function testHasScopeClaimPrecedenceIsScpThenScopesThenScope() : void
    {
        // The first claim present wins, later ones are not consulted as a fallback
        $token = JwtFactory::mint(["scp" => "other-scope", "scope" => "test-scope"]);

        $this->assertDenied($this->request("hasScope", $token), 403, "insufficientScope");
    }

    public function testHasScopeWithoutUsableScopesDeniesEveryone() : void
    {
        // Empty entries in the attribute are dropped, and a token's empty entries (double space) must not match them
        foreach(["x  y", "", "test-scope"] as $scopes)
            $this->assertDenied($this->request("hasNoUsableScope", JwtFactory::mint(["scp" => $scopes])), 403, "insufficientScope");
    }

    #[DataProvider('anyScopeRoutes')]
    public function testHasAnyScopeMatchesAnyOfTheRequiredScopes(string $method) : void
    {
        $this->assertAllowed($this->request($method, JwtFactory::mint(["scp" => "read"])));
        $this->assertAllowed($this->request($method, JwtFactory::mint(["scp" => "write"])));
        $this->assertAllowed($this->request($method, JwtFactory::mint(["scp" => "delete read"])));
        $this->assertDenied($this->request($method, JwtFactory::mint(["scp" => "delete"])), 403, "insufficientScope");
    }

    public static function anyScopeRoutes() : array
    {
        return [
            "comma-separated string" => ["hasAnyScope"],
            "array" => ["hasScopeArray"],
        ];
    }

    // ---------------------------------------------------------------------
    // HasRole
    // ---------------------------------------------------------------------

    #[DataProvider('roleClaimShapes')]
    public function testHasRoleAcceptsSupportedClaimShapes(array $claims) : void
    {
        $this->assertAllowed($this->request("hasRole", JwtFactory::mint($claims)));
    }

    public static function roleClaimShapes() : array
    {
        return [
            "roles string" => [["roles" => "test-role"]],
            "role string" => [["role" => "test-role"]],
            "roles array" => [["roles" => ["other", "test-role"]]],
            "role array" => [["role" => ["test-role"]]],
            "space delimited" => [["roles" => "other test-role"]],
            "comma delimited" => [["roles" => "other,test-role"]],
        ];
    }

    #[DataProvider('roleClaimsThatDoNotGrantTestRole')]
    public function testHasRoleDeniesInsufficientRole(array $claims) : void
    {
        $this->assertDenied($this->request("hasRole", JwtFactory::mint($claims)), 403, "insufficientRole");
    }

    public static function roleClaimsThatDoNotGrantTestRole() : array
    {
        return [
            "no role claim" => [[]],
            "empty role" => [["roles" => ""]],
            "empty role array" => [["roles" => []]],
            "other role" => [["roles" => "other-role"]],
            "prefix of required" => [["roles" => "test"]],
            "extension of required" => [["roles" => "test-role-extra"]],
            "case differs" => [["roles" => "TEST-ROLE"]],
            "role is not a string or array" => [["roles" => 7]],
            "boolean role does not match any role" => [["roles" => [true]]],
            "array with a non-string entry" => [["roles" => ["test-role", 7]]],
            "scope claim is not a role" => [["scp" => "test-role"]],
        ];
    }

    public function testHasRoleClaimPrecedenceIsRolesThenRole() : void
    {
        $token = JwtFactory::mint(["roles" => "other-role", "role" => "test-role"]);

        $this->assertDenied($this->request("hasRole", $token), 403, "insufficientRole");
    }

    #[DataProvider('anyRoleRoutes')]
    public function testHasAnyRoleMatchesAnyOfTheRequiredRoles(string $method) : void
    {
        $this->assertAllowed($this->request($method, JwtFactory::mint(["roles" => "admin"])));
        $this->assertAllowed($this->request($method, JwtFactory::mint(["roles" => ["editor"]])));
        $this->assertAllowed($this->request($method, JwtFactory::mint(["roles" => "viewer editor"])));
        $this->assertDenied($this->request($method, JwtFactory::mint(["roles" => "viewer"])), 403, "insufficientRole");
    }

    public static function anyRoleRoutes() : array
    {
        return [
            "comma-separated string" => ["hasAnyRole"],
            "array" => ["hasRoleArray"],
        ];
    }

    // ---------------------------------------------------------------------
    // HasScope + HasRole on one route
    // ---------------------------------------------------------------------

    public function testScopeAndRoleAttributesMustBothPass() : void
    {
        $this->assertAllowed($this->request("hasScopeAndRole", JwtFactory::mint(["scp" => "test-scope", "roles" => "test-role"])));

        $this->assertDenied(
            $this->request("hasScopeAndRole", JwtFactory::mint(["scp" => "test-scope", "roles" => "other-role"])),
            403,
            "insufficientRole"
        );

        $this->assertDenied(
            $this->request("hasScopeAndRole", JwtFactory::mint(["scp" => "other-scope", "roles" => "test-role"])),
            403,
            "insufficientScope"
        );
    }
}
