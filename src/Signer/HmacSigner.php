<?php

namespace Nimbly\Proof\Signer;

use Nimbly\Proof\SignerInterface;
use ParagonIE\HiddenString\HiddenString;
use RuntimeException;

class HmacSigner implements SignerInterface
{
	/**
	 * Map of supported algorithms.
	 *
	 * @var array<string,string>
	 */
	private $supported_algorithms = [
		"SHA256" => "HS256",
		"SHA384" => "HS384",
		"SHA512" => "HS512"
	];

	/**
	 * Algorithm to use for hashing.
	 *
	 * @var string
	 */
	protected string $algorithm;

	/**
	 * The key to use for hashing.
	 *
	 * @var HiddenString
	 */
	protected HiddenString $key;

	/**
	 * Hmac constructor.
	 *
	 * @param string $algorithm The algorithm to use for signing messages. Can be SHA256, SHA384, or SHA512.
	 * @param string $key The shared key to use for signing.
	 */
	public function __construct(
		string $algorithm,
		string $key
	)
	{
		if( \array_key_exists($algorithm, $this->supported_algorithms) === false ){
			throw new RuntimeException("Unsupported algorithm \"{$algorithm}\".");
		}

		$this->algorithm = $algorithm;
		$this->key = new HiddenString($key);
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
		return \hash_hmac(
			$this->algorithm,
			$message,
			$this->key->getString(),
			true
		);
	}

	/**
	 * @inheritDoc
	 */
	public function verify(string $message, string $signature): bool
	{
		return $this->sign($message) === $signature;
	}
}