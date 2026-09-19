<?php
declare(strict_types=1);

use gijsbos\ApiServer\OAuth2\Components\AccessTokenClaimToListConverter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * AccessTokenClaimToListConverterTest
 */
class AccessTokenClaimToListConverterTest extends TestCase
{
    #[DataProvider('claims')]
    public function testClaimToList(mixed $claim, null|array $expected) : void
    {
        $this->assertSame($expected, AccessTokenClaimToListConverter::convert($claim));
    }

    public static function claims() : array
    {
        return [
            "single value" => ["a", ["a"]],
            "space delimited" => ["a b c", ["a", "b", "c"]],
            "comma delimited" => ["a,b,c", ["a", "b", "c"]],
            "mixed delimiters" => ["a, b  c,,d", ["a", "b", "c", "d"]],
            "leading and trailing delimiters" => [" a b, ", ["a", "b"]],
            "empty string" => ["", []],
            "only delimiters" => [" , ", []],
            "array" => [["a", "b"], ["a", "b"]],
            "array drops empty entries and reindexes" => [["a", "", "b"], ["a", "b"]],
            "array keeps entries containing spaces intact" => [["a b"], ["a b"]],
            "empty array" => [[], []],
            "array with an int" => [["a", 1], null],
            "array with a bool" => [[true], null],
            "array with null" => [[null], null],
            "array with a nested array" => [[["a"]], null],
            "int" => [5, null],
            "bool" => [true, null],
            "null" => [null, null],
        ];
    }
}
