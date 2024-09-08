<?php

use Nimbly\Proof\Proof;
use Nimbly\Proof\Signer\HmacSigner;
use Nimbly\Proof\SigningException;
use PHPUnit\Framework\TestCase;

/**
 * @covers Nimbly\Proof\Signer\HmacSigner
 */
class HmacSignerTest extends TestCase
{
	public function test_constructor_throws_exception_if_alogrithm_is_not_supported(): void
	{
		$this->expectException(SigningException::class);

		$hmacSigner = new HmacSigner(
			"SHA128",
			"supersecretkey"
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

	public function test_is_algorithm_supported_returns_true_for_supported_algorithms(): void
	{
		$keypairSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("HS256")
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("HS384")
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("HS512")
		);
	}

	public function test_is_algorithm_supported_returns_false_for_unsupported_algorithms(): void
	{
		$keypairSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$this->assertFalse(
			$keypairSigner->isAlgorithmSupported("RS128")
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

	public function test_verify_returns_false_with_different_key(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$message = "Message";

		$signature = $hmacSigner->sign($message);

		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"bologne1"
		);

		$this->assertFalse(
			$hmacSigner->verify($message, $signature)
		);
	}

	public function test_verify_returns_false_with_tampered_message(): void
	{
		$hmacSigner = new HmacSigner(
			Proof::ALGO_SHA256,
			"supersecretkey"
		);

		$message = "Message";

		$signature = $hmacSigner->sign($message);

		$this->assertFalse(
			$hmacSigner->verify("Tampered message", $signature)
		);
	}
}