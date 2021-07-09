<?php

use PHPUnit\Framework\TestCase;
use Nimbly\Proof\Proof;
use Nimbly\Proof\Signer\HmacSigner;

/**
 * @covers Nimbly\Proof\Signer\HmacSigner
 */
class HmacSignerTest extends TestCase
{
	public function test_constructor_sets_algorithm_property(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$reflectionClass = new ReflectionClass($hmacSigner);
		$reflectionProperty = $reflectionClass->getProperty("algorithm");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			Proof::ALGO_SHA256,
			$reflectionProperty->getValue($hmacSigner)
		);
	}

	public function test_constructor_sets_key_property_as_hidden_string(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$reflectionClass = new ReflectionClass($hmacSigner);
		$reflectionProperty = $reflectionClass->getProperty("key");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			"supersecretkey",
			$reflectionProperty->getValue($hmacSigner)->getString()
		);
	}

	public function test_get_algorithm_returns_hs256_for_sha256(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$this->assertEquals(
			"HS256",
			$hmacSigner->getAlgorithm()
		);
	}

	public function test_get_algorithm_returns_hs384_for_sha384(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA384,
			"supersecretkey"
		);

		$this->assertEquals(
			"HS384",
			$hmacSigner->getAlgorithm()
		);
	}

	public function test_get_algorithm_returns_hs512_for_sha512(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA512,
			"supersecretkey"
		);

		$this->assertEquals(
			"HS512",
			$hmacSigner->getAlgorithm()
		);
	}

	public function test_sign_and_verify(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$message = "Message";

		$signature = $hmacSigner->sign($message);

		$this->assertTrue(
			$hmacSigner->verify($message, $signature)
		);
	}
}