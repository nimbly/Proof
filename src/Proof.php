<?php

namespace Nimbly\Proof;

class Proof
{
	const ALGO_SHA256 = "SHA256";
	const ALGO_SHA384 = "SHA384";
	const ALGO_SHA512 = "SHA512";

	/**
	 * @param SignerInterface $signer The default signing key used for encoding and decoding tokens.
	 * @param integer $leeway Time in seconds to add to expiration and "not-before" date calculations to account for drift. The leeway can be negative if you wish.
	 * @param array<string,SignerInterface> $keyMap If you're using multiple different signing keys, you can map them here as key/value pairs. If no kid is present in header or no kid provided when signing, then the default signing key will be used.
	 */
	public function __construct(
		protected SignerInterface $signer,
		protected int $leeway = 0,
		protected array $keyMap = [])
	{
	}

	/**
	 * Encode a Token instance into a JWT.
	 *
	 * @param Token $token
	 * @param string|null $kid Key ID to include in header
	 * @throws TokenEncodingException
	 * @return string
	 */
	public function encode(Token $token, ?string $kid = null): string
	{
		if( $kid ) {
			$signer = $this->getSignerByKeyId($kid);

			if( empty($signer) ){
				throw new SignerNotFoundException("No signer found for key ID.");
			}
		}
		else {
			$signer = $this->signer;
		}

		$header = [
			"algo" => $signer->getAlgorithm(),
			"typ" => "JWT"
		];

		if( $kid ) {
			$header["kid"] = $kid;
		}

		$header = \json_encode($header);
		$payload = \json_encode($token);

		if( $header === false || $payload === false ){
			throw new TokenEncodingException("Failed to JSON encode token.");
		}

		// Build the header and payload portion of the JWT.
		$jwt = $this->base64UrlEncode($header) . "." .
				$this->base64UrlEncode($payload);

		// Compute the signature of the header and the payload.
		$signature = $signer->sign($jwt);

		return $jwt . "." . $this->base64UrlEncode($signature);
	}

	/**
	 * Decode a JWT string into a Token instance.
	 *
	 * @param string $jwt
	 * @throws InvalidTokenException
	 * @throws SignatureMismatchException
	 * @throws ExpiredTokenException
	 * @throws TokenNotReadyException
	 * @return Token
	 */
	public function decode(string $jwt): Token
	{
		$parts = \explode(".", $jwt);

		if( \count($parts) < 3 ){
			throw new InvalidTokenException("Invalid number of token parts.");
		}

		[$header, $payload, $signature] = $parts;

		$decoded_header = \json_decode($this->base64UrlDecode($header));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("Token header could not be JSON decoded.");
		}

		if( isset($decoded_header->kid) ){
			$signer = $this->getSignerByKeyId($decoded_header->kid);

			if( empty($signer) ){
				throw new SignerNotFoundException("No signer found for decoding.");
			}
		}
		else {
			$signer = $this->signer;
		}

		$signature_verified = $signer->verify(
			"{$header}.{$payload}",
			$this->base64UrlDecode($signature)
		);

		if( !$signature_verified ){
			throw new SignatureMismatchException("Token signature mismatch.");
		}

		/**
		 * @var object $decoded_payload
		 */
		$decoded_payload = \json_decode($this->base64UrlDecode($payload));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("The token payload could not be JSON decoded.");
		}

		$timestamp = \time();

		if( isset($decoded_payload->exp) &&
			$decoded_payload->exp < ($timestamp + $this->leeway) ){
			throw new ExpiredTokenException("The token has expired.");
		}

		if( isset($decoded_payload->nbf) &&
			$decoded_payload->nbf > ($timestamp - $this->leeway) ){
			throw new TokenNotReadyException("The token is not ready to be accepted yet.");
		}

		return new Token((array) $decoded_payload);
	}

	/**
	 * Get a SignerInterface instance by its Key ID (kid) from the key map.
	 *
	 * @param string $kid
	 * @return SignerInterface|null
	 */
	private function getSignerByKeyId(string $kid): ?SignerInterface
	{
		return $this->keyMap[$kid] ?? null;
	}

	/**
	 * Apply a URL safe transform to a base64 encoding.
	 * Includes stripping of base64 "=" padding.
	 *
	 * @param string $string
	 * @return string
	 */
	private function base64UrlEncode(string $string): string
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
	private function base64UrlDecode(string $string): string
	{
		return \base64_decode(
			\str_replace(
				["_", "-", "="],
				["/", "+", ""],
				$string
			)
		);
	}
}