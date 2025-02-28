<?php

namespace Nimbly\Proof\Signer;

use Nimbly\Proof\SignerInterface;
use Nimbly\Proof\SigningException;
use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;

class HmacSigner implements SignerInterface
{
	/**
	 * Map of supported algorithms.
	 *
	 * @var array<string,string>
	 */
	private array $supported_algorithms = [
		"SHA256" => "HS256",
		"SHA384" => "HS384",
		"SHA512" => "HS512"
	];

	protected HiddenString $key;

	/**
	 * @param string $algorithm The algorithm to use for signing messages. Can be SHA256, SHA384, or SHA512.
	 * @param string $key The shared key to use for signing.
	 * @throws SigningException
	 */
	public function __construct(
		protected string $algorithm,
		#[SensitiveParameter] string $key
	)
	{
		if( \array_key_exists($algorithm, $this->supported_algorithms) === false ){
			throw new SigningException("Unsupported algorithm \"{$algorithm}\".");
		}

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
		return \hash_equals(
			$this->sign($message),
			$signature
		);
	}
}