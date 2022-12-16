<?php

namespace Nimbly\Proof\Signer;

use Nimbly\Proof\SignerInterface;
use Nimbly\Proof\SigningException;
use OpenSSLAsymmetricKey;

class KeypairSigner implements SignerInterface
{
	/**
	 * Map of supported algorithms.
	 *
	 * @var array<string,string>
	 */
	private array $supported_algorithms = [
		"SHA256" => "RS256",
		"SHA384" => "RS384",
		"SHA512" => "RS512"
	];

	/**
	 * @param string $algorithm Algorithm to use when signing: SHA256, SHA384, SHA512
	 * @param OpenSSLAsymmetricKey|null $private_key Private key instance
	 * @param OpenSSLAsymmetricKey|null $public_key Public key instance
	 */
	public function __construct(
		protected string $algorithm,
		protected ?OpenSSLAsymmetricKey $public_key = null,
		protected ?OpenSSLAsymmetricKey $private_key = null
	)
	{
		if( \array_key_exists($algorithm, $this->supported_algorithms) === false ){
			throw new SigningException("Unsupported algorithm \"{$algorithm}\".");
		}
	}

	/**
	 * @inheritDoc
	 */
	public function getAlgorithm(): string
	{
		return $this->supported_algorithms[$this->algorithm];
	}

	/**
	 * @inheritDoc
	 */
	public function isAlgorithmSupported(string $algorithm): bool
	{
		return \in_array($algorithm, $this->supported_algorithms);
	}

	/**
	 * @inheritDoc
	 */
	public function sign(string $message): string
	{
		$signature = "";

		if( empty($this->private_key) ){
			throw new SigningException("No private key provided to sign with.");
		}

		$status = \openssl_sign(
			$message,
			$signature,
			$this->private_key,
			$this->algorithm
		);

		if( $status === false ){
			throw new SigningException("Failed to sign the message.");
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

		$status = \openssl_verify(
			$message,
			$signature,
			$this->public_key,
			$this->algorithm
		);

		if( $status < 0 ){
			throw new SigningException("An error occured when trying to verify signature of message.");
		}

		return (bool) $status;
	}
}