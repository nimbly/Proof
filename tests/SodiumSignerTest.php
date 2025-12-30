<?php

use Nimbly\Proof\Proof;
use PHPUnit\Framework\TestCase;
use Nimbly\Proof\SigningException;
use Nimbly\Proof\Signer\SodiumSigner;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SodiumSigner::class)]
class SodiumSignerTest extends TestCase
{
	public function test_get_algorithm_returns_eddsa(): void
	{
		$signer = new SodiumSigner;

		$this->assertEquals(
			Proof::ALGO_EDDSA,
			$signer->getAlgorithm()
		);
	}

	public function test_is_algorithm_supported_returns_true(): void
	{
		$signer = new SodiumSigner;
		$this->assertTrue($signer->isAlgorithmSupported(Proof::ALGO_EDDSA));
	}

	public function test_is_algorithm_supported_returns_true_for_deprecated_eddsa(): void
	{
		$signer = new SodiumSigner;
		$this->assertTrue($signer->isAlgorithmSupported("EdDSA"));
	}

	public function test_is_algorithm_supported_returns_false(): void
	{
		$signer = new SodiumSigner;
		$this->assertFalse($signer->isAlgorithmSupported(Proof::ALGO_SHA256));
	}

	public function test_sign_with_no_secret_key_throws_signing_exception(): void
	{
		$signer = new SodiumSigner;
		$this->expectException(SigningException::class);
		$signer->sign("Message");
	}

	public function test_sign(): void
	{
		$keypair = \sodium_crypto_sign_keypair();
		$secret_key = \sodium_crypto_sign_secretkey($keypair);

		$signer = new SodiumSigner(
			secret_key: $secret_key
		);

		$signature = $signer->sign("My message");
		$this->assertNotEmpty($signature);
	}

	public function test_sign_throws_signing_exception_if_invalid_secret_key(): void
	{
		$signer = new SodiumSigner(
			secret_key: "not_a_secret_key"
		);

		$this->expectException(SigningException::class);
		$signer->sign("Message");
	}

	public function test_verify_with_no_secret_key_throws_signing_exception(): void
	{
		$signer = new SodiumSigner;
		$this->expectException(SigningException::class);
		$signer->verify("Message", "Signature");
	}

	public function test_verify_returns_true_on_good_signature(): void
	{
		$keypair = \sodium_crypto_sign_keypair();

		$secret_key = \sodium_crypto_sign_secretkey($keypair);
		$public_key = \sodium_crypto_sign_publickey($keypair);

		$signer = new SodiumSigner(
			secret_key: $secret_key,
			public_key: $public_key,
		);

		$signature = $signer->sign("My message");

		$valid = $signer->verify("My message", $signature);

		$this->assertTrue($valid);
	}

	public function test_verify_returns_false_on_bad_signature(): void
	{
		$keypair = \sodium_crypto_sign_keypair();

		$secret_key = \sodium_crypto_sign_secretkey($keypair);
		$public_key = \sodium_crypto_sign_publickey($keypair);

		$signer = new SodiumSigner(
			secret_key: $secret_key,
			public_key: $public_key,
		);

		$signature = $signer->sign("My message");

		$valid = $signer->verify("My other message", $signature);

		$this->assertFalse($valid);
	}

	public function test_verify_throws_signing_exception_if_invalid_public_key(): void
	{
		$signer = new SodiumSigner(public_key: "not_a_public_key");

		$this->expectException(SigningException::class);
		$signer->verify("Message", "Signature");
	}
}