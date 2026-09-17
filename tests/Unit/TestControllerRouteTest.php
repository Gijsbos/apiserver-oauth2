<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\Parsers\RouteParser;
use gijsbos\Http\Http\HTTPRequest;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * TestControllerRouteTest
 *  The name cannot be the same as the auto generated TestControllerTest class, hence TestControllerRouteTest
 */
class TestControllerRouteTest extends TestCase
{
    public static function setupBeforeClass() : void
    {

    }

    private function createTestJwt(string $scopes = "", string $roles = ""): string
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);

        $payload = [
            'iss' => 'https://example.com',
            'sub' => 'test-user',
            'aud' => 'test-client',
            'iat' => time(),
            'exp' => time() + 3600,
        ];

        if(strlen($scopes))
            $payload["scp"] = $scopes;

        if(strlen($roles))
            $payload["roles"] = $roles;

        $jws =  (new JWSBuilder($algorithmManager))
                ->create()
                ->withPayload(json_encode($payload))
                ->addSignature(EXAMPLE_KEY_SET, [
                    'alg' => 'RS256',
                    'kid' => EXAMPLE_KEY_SET->get('kid'),
                ])
                ->build();

        return (new CompactSerializer())->serialize($jws);
    }

    public function testHasScope() : void
    {
        # Header Params
        $token = $this->createTestJwt("test-scope");

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasScope'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertTrue($response->isSuccessful());
    }

    public function testHasScopeFails() : void
    {
        # Header Params
        $token = "token";

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasScope'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertFalse($response->isSuccessful(), $response->getErrorString());
    }

    public function testHasScopeInsufficientPermissions() : void
    {
        # Header Params
        $token = $this->createTestJwt("other-scope");

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasScope'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertFalse($response->isSuccessful(), $response->getErrorString());
        $this->assertEquals("insufficient_scope", $response->getError());
    }

    public function testHasRole() : void
    {
        # Header Params
        $token = $this->createTestJwt("", "test-role");

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasRole'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertTrue($response->isSuccessful());
    }

    public function testHasRoleFails() : void
    {
        # Header Params
        $token = "token";

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasRole'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertFalse($response->isSuccessful(), $response->getErrorString());
    }

    public function testHasRoleInsufficientPermissions() : void
    {
        # Header Params
        $token = $this->createTestJwt("", "other-role");

        # Send Request
        $response = HTTPRequest::get([
            "uri" => RouteParser::getRoute(['TestController', 'hasRole'])->getFullPath(false),
            "headers" => [
                "Authorization" => "Bearer $token",
            ]
        ]);

        # Test Result
        $this->assertFalse($response->isSuccessful(), $response->getErrorString());
        $this->assertEquals("insufficient_role", $response->getError());
    }
}