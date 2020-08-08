<?php

use PHPUnit\Framework\TestCase;
use Nimbly\Proof\Proof;
use Nimbly\Proof\Signer\KeypairSigner;

/**
 * @covers Nimbly\Proof\Signer\KeypairSigner
 */
class KeypairSignerTest extends TestCase
{
	public function test_constructor_sets_algorithm_property(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\file_get_contents(__DIR__ . "/public.pem"),
			\file_get_contents(__DIR__ . "/private.pem")
		);

		$reflectionClass = new ReflectionClass($keypairSigner);
		$reflectionProperty = $reflectionClass->getProperty("algorithm");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			Proof::ALGO_SHA256,
			$reflectionProperty->getValue($keypairSigner)
		);
	}

	public function test_constructor_sets_public_key_property(): void
	{
		$public_key = \file_get_contents(__DIR__ . "/public.pem");

		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			$public_key
		);

		$reflectionClass = new ReflectionClass($keypairSigner);
		$reflectionProperty = $reflectionClass->getProperty("public_key");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			$public_key,
			$reflectionProperty->getValue($keypairSigner)
		);
	}

	public function test_constructor_sets_private_key_property(): void
	{
		$private_key = \file_get_contents(__DIR__ . "/private.pem");

		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\file_get_contents(__DIR__ . "/public.pem"),
			$private_key
		);

		$reflectionClass = new ReflectionClass($keypairSigner);
		$reflectionProperty = $reflectionClass->getProperty("private_key");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			$private_key,
			$reflectionProperty->getValue($keypairSigner)
		);
	}

	public function test_get_algorithm_returns_hs256_for_sha256(): void
	{
		$keypairSigner = new KeypairSigner(
			Proof::ALGO_SHA256,
			\file_get_contents(__DIR__ . "/public.pem"),
			\file_get_contents(__DIR__ . "/private.pem")
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
			\file_get_contents(__DIR__ . "/public.pem"),
			\file_get_contents(__DIR__ . "/private.pem")
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
			\file_get_contents(__DIR__ . "/public.pem"),
			\file_get_contents(__DIR__ . "/private.pem")
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
			\file_get_contents(__DIR__ . "/public.pem"),
			\file_get_contents(__DIR__ . "/private.pem")
		);

		$message = "Message";

		$signature = $keypairSigner->sign($message);

		$this->assertTrue(
			$keypairSigner->verify($message, $signature)
		);
	}
}