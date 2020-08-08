<?php

namespace Nimbly\Proof\Signer;

use Nimbly\Proof\SignerInterface;
use RuntimeException;

class KeypairSigner implements SignerInterface
{
	/**
	 * Map of supported algorithms.
	 *
	 * @var array<string,string>
	 */
	private $supported_algorithms = [
		"SHA256" => "RS256",
		"SHA384" => "RS384",
		"SHA512" => "RS512"
	];

	/**
	 * Algorithm to use for signing token.
	 *
	 * @var string
	 */
	protected $algorithm;

	/**
	 * Public key.
	 *
	 * @var string
	 */
	protected $public_key;

	/**
	 * Private key.
	 *
	 * @var string|null
	 */
	protected $private_key;

	/**
	 * KeypairSigner constructor.
	 *
	 * @param string $algorithm Algorithm to use when signing: SHA256, SHA384, SHA512
	 * @param string $public_key Public key contents.
	 * @param string|null $private_key Private key contents.
	 */
	public function __construct(
		string $algorithm,
		string $public_key,
		?string $private_key = null
	)
	{
		if( \array_key_exists($algorithm, $this->supported_algorithms) === false ){
			throw new RuntimeException("Unsupported algorithm \"{$algorithm}\".");
		}

		$this->algorithm = $algorithm;
		$this->public_key = $public_key;
		$this->private_key = $private_key;
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
		if( empty($this->private_key) ){
			throw new RuntimeException("Cannot sign message: private key has not been provided.");
		}

		$signature = "";

		$status = \openssl_sign(
			$message,
			$signature,
			$this->private_key,
			$this->algorithm
		);

		if( $status === false ){
			throw new RuntimeException("Failed to sign the message.");
		}

		return $signature;
	}

	/**
	 * @inheritDoc
	 */
	public function verify(string $message, string $signature): bool
	{
		$status = \openssl_verify(
			$message,
			$signature,
			$this->public_key,
			$this->algorithm
		);

		if( $status < 0 ){
			throw new RuntimeException("An error occured when trying to verify signature of message.");
		}

		return (bool) $status;
	}
}