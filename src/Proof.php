<?php

namespace Nimbly\Proof;

class Proof
{
	const ALGO_SHA256 = "SHA256";
	const ALGO_SHA384 = "SHA384";
	const ALGO_SHA512 = "SHA512";

	public function __construct(
		protected SignerInterface $signer,
		protected int $leeway = 0)
	{
	}

	/**
	 * Encode a Token instance into a JWT.
	 *
	 * @param Token $token
	 * @return string
	 */
	public function encode(Token $token): string
	{
		$header = \json_encode([
				"algo" => $this->signer->getAlgorithm(),
				"typ" => "JWT"
			]);

		$payload = \json_encode($token);

		// Build the header and payload portion of the JWT.
		$jwt = $this->base64_url_encode($header) . "." .
				$this->base64_url_encode($payload);

		// Compute the signature of the header and the payload.
		$signature = $this->signer->sign($jwt);

		return $jwt . "." . $this->base64_url_encode($signature);
	}

	/**
	 * Decode a JWT string into a Token instance.
	 *
	 * @param string $jwt
	 * @return Token
	 */
	public function decode(string $jwt): Token
	{
		$parts = \explode(".", $jwt);

		if( \count($parts) < 3 ){
			throw new InvalidTokenException("Invalid number of token parts.");
		}

		[$header, $payload, $signature] = $parts;

		$signature_verified = $this->signer->verify(
			"{$header}.{$payload}",
			$this->base64_url_decode($signature)
		);

		if( !$signature_verified ){
			throw new SignatureMismatchException("Token signature mismatch.");
		}

		$payload = \json_decode($this->base64_url_decode($payload));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("The token payload could not be decoded.");
		}

		$timestamp = \time() + $this->leeway;

		if( isset($payload->exp) &&
			$payload->exp < $timestamp ){
			throw new ExpiredTokenException("The token has expired.");
		}

		if( isset($payload->nbf) &&
			$payload->nbf > $timestamp ){
			throw new TokenNotReadyException("The token is not ready to be accepted yet.");
		}

		return new Token((array) $payload);
	}

	/**
	 * Apply a URL safe transform to a base64 encoding.
	 *
	 * @param string $string
	 * @return string
	 */
	private function base64_url_encode(string $string): string
	{
		return \str_replace(
			["/", "+"],
			["_", "-"],
			\base64_encode($string)
		);
	}

	/**
	 * Apply a URL safe transform on a base64 decode.
	 *
	 * @param string $string
	 * @return string
	 */
	private function base64_url_decode(string $string): string
	{
		return \base64_decode(
			\str_replace(
				["_", "-"],
				["/", "+"],
				$string
			)
		);
	}

	private function decodeHeader(string $header): object
	{
		$header = \json_decode($this->base64_url_decode($header));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("Could not decode token header.");
		}

		if( !isset($header->algo) ){
			throw new InvalidTokenException("Token missing algorithm in header.");
		}

		if( !$this->signer->isAlgorithmSupported($header->algo) ){
			throw new InvalidTokenException("Token has unsupported algorithm.");
		}

		return $header;
	}
}