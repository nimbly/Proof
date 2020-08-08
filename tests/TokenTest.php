<?php

use PHPUnit\Framework\TestCase;
use Nimbly\Proof\Token;

/**
 * @covers Nimbly\Proof\Token
 */
class TokenTest extends TestCase
{
	public function test_constructor_sets_claims(): void
	{
		$token = new Token(["sub" => 12345]);

		$reflectionClass = new ReflectionClass($token);
		$reflectionProperty = $reflectionClass->getProperty("claims");
		$reflectionProperty->setAccessible(true);
		$claims = $reflectionProperty->getValue($token);

		$this->assertEquals(
			["sub" => 12345],
			$claims
		);
	}

	public function test_has_claim_found_returns_true(): void
	{
		$token = new Token(["sub" => 12345]);
		$this->assertTrue($token->hasClaim("sub"));
	}

	public function test_has_claim_not_found_returns_false(): void
	{
		$token = new Token;
		$this->assertFalse($token->hasClaim("sub"));
	}

	public function test_get_claim_found_returns_value(): void
	{
		$token = new Token(["sub" => 12345]);
		$this->assertEquals(
			12345,
			$token->getClaim("sub")
		);
	}

	public function test_get_claim_not_found_returns_null(): void
	{
		$token = new Token;
		$this->assertNull(
			$token->getClaim("sub")
		);
	}

	public function test_set_claim(): void
	{
		$token = new Token;

		$token->setClaim("sub", 12345);

		$this->assertEquals(
			12345,
			$token->getClaim("sub")
		);
	}

	public function test_set_claim_replaces_value(): void
	{
		$token = new Token(["sub" => 45678]);
		$token->setClaim("sub", 12345);

		$this->assertEquals(
			12345,
			$token->getClaim("sub")
		);
	}

	public function test_to_array_returns_all_claims(): void
	{
		$token = new Token(["sub" => 12345, "jti" => "abc123"]);

		$this->assertEquals(
			["sub" => 12345, "jti" => "abc123"],
			$token->toArray()
		);
	}
}