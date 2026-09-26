<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use gijsbos\ApiServer\OAuth2\Enums\GrantType;

/**
 * GrantTypeTest
 */
class GrantTypeTest extends TestCase
{
    public function testFromListParsesAndDeduplicates() : void
    {
        $this->assertEquals(
            [GrantType::AuthorizationCode, GrantType::RefreshToken],
            GrantType::fromList(" authorization_code , refresh_token,authorization_code ")
        );
    }

    public function testFromListOfAnEmptyStringIsEmpty() : void
    {
        $this->assertEquals([], GrantType::fromList(" , "));
    }

    public function testFromListRejectsUnknownGrantTypes() : void
    {
        // Implicit is deliberately not supported
        $this->expectException(InvalidArgumentException::class);

        GrantType::fromList("authorization_code,implicit");
    }

    public function testValues() : void
    {
        $this->assertEquals(
            ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            GrantType::values([GrantType::ClientCredentials, GrantType::JwtBearer])
        );
    }
}
