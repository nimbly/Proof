<?php

use PHPUnit\Framework\TestCase;
use Nimbly\Proof\Proof;
use Nimbly\Proof\Signer\KeypairSigner;
use Nimbly\Proof\SigningException;

/**
 * @covers Nimbly\Proof\Signer\KeypairSigner
 */
class KeypairSignerTest extends TestCase
{
	public function test_constructor_throws_exception_if_alogrithm_is_not_supported(): void
	{
		$this->expectException(SigningException::class);

		$keypairSigner = new KeypairSigner(
			"SHA128",
			\openssl_get_privatekey(\file_get_contents(__DIR__ . "/private.pem"))
		);
	}

	public function test_get_algorithm_returns_hs256_for_sha256(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\openssl_get_privatekey(\file_get_contents(__DIR__ . "/private.pem"))
		);

		$this->assertEquals(
			"RS256",
			$keypairSigner->getAlgorithm()
		);
	}

	public function test_get_algorithm_returns_hs384_for_sha384(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA384,
			\openssl_get_privatekey(\file_get_contents(__DIR__ . "/private.pem"))
		);

		$this->assertEquals(
			"RS384",
			$keypairSigner->getAlgorithm()
		);
	}

	public function test_get_algorithm_returns_hs512_for_sha512(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA512,
			\openssl_get_privatekey(\file_get_contents(__DIR__ . "/private.pem"))
		);

		$this->assertEquals(
			"RS512",
			$keypairSigner->getAlgorithm()
		);
	}

	public function test_sign_and_verify(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\openssl_get_publickey(\file_get_contents(__DIR__ . "/public.pem")),
			\openssl_get_privatekey(\file_get_contents(__DIR__ . "/private.pem"))
		);

		$message = "Message";

		$signature = $keypairSigner->sign($message);

		$this->assertTrue(
			$keypairSigner->verify($message, $signature)
		);
	}

	public function test_is_algorithm_supported_returns_true_for_supported_algorithms(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\openssl_get_publickey(\file_get_contents(__DIR__ . "/public.pem"))
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("RS256")
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("RS384")
		);

		$this->assertTrue(
			$keypairSigner->isAlgorithmSupported("RS512")
		);
	}

	public function test_is_algorithm_supported_returns_false_for_unsupported_algorithms(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\openssl_get_publickey(\file_get_contents(__DIR__ . "/public.pem"))
		);

		$this->assertFalse(
			$keypairSigner->isAlgorithmSupported("RS128")
		);
	}

	public function test_signing_with_no_private_key_throws_signing_exception(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\openssl_get_publickey(\file_get_contents(__DIR__ . "/public.pem"))
		);

		$this->expectException(SigningException::class);
		$keypairSigner->sign("Message");
	}

	public function test_verify_with_no_public_key_throws_signing_exception(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256
		);

		$this->expectException(SigningException::class);
		$keypairSigner->verify("Message", "signature");
	}
}