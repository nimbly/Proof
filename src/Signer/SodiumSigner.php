<?php

namespace Nimbly\Proof\Signer;

use Nimbly\Proof\SignerInterface;
use Nimbly\Proof\SigningException;
use SensitiveParameter;
use SodiumException;

class SodiumSigner implements SignerInterface
{
	public function __construct(
		#[SensitiveParameter] private ?string $secret_key = null,
		#[SensitiveParameter] private ?string $public_key = null,
	)
	{
	}

	/**
	 * @inheritDoc
	 */
	public function getAlgorithm(): string
	{
		return "Ed25519";
	}

	/**
	 * @inheritDoc
	 */
	public function isAlgorithmSupported(string $algorithm): bool
	{
		return $algorithm === "EdDSA" || $algorithm === "Ed25519";
	}

	/**
	 * @inheritDoc
	 */
	public function sign(string $message): string
	{
		if( empty($this->secret_key) ){
			throw new SigningException("No secret key provided to sign with.");
		}

		try {

			$signature = \sodium_crypto_sign_detached($message, $this->secret_key);
		}
		catch( SodiumException $exception ){
			throw new SigningException(
				message: "Failed to sign message.",
				previous: $exception
			);
		}

		return $signature;
	}

	/**
	 * @inheritDoc
	 */
	public function verify(string $message, string $signature): bool
	{
		if( empty($this->public_key) ){
			throw new SigningException("No public key provided to verify with.");
		}

		try {

			$result = \sodium_crypto_sign_verify_detached($signature, $message, $this->public_key);
		}
		catch( SodiumException $exception ){
			throw new SigningException(
				message: "An error occured when trying to verify signature of message.",
				previous: $exception
			);
		}

		return $result;
	}
}