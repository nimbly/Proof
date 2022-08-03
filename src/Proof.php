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

		/**
		 * @var object $decoded_payload
		 */
		$decoded_payload = \json_decode($this->base64_url_decode($payload));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("The token payload could not be decoded.");
		}

		$timestamp = \time() + $this->leeway;

		if( isset($decoded_payload->exp) &&
			$decoded_payload->exp < $timestamp ){
			throw new ExpiredTokenException("The token has expired.");
		}

		if( isset($decoded_payload->nbf) &&
			$decoded_payload->nbf > $timestamp ){
			throw new TokenNotReadyException("The token is not ready to be accepted yet.");
		}

		return new Token((array) $decoded_payload);
	}

	/**
	 * Apply a URL safe transform to a base64 encoding.
	 * Includes stripping of base64 "=" padding.
	 *
	 * @param string $string
	 * @return string
	 */
	private function base64_url_encode(string $string): string
	{
		return \str_replace(
			["/", "+", "="],
			["_", "-", ""],
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
}