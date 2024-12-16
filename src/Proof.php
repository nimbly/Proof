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
	 * @param array<string,SignerInterface> $keyMap If you're using multiple different signing keys, you can map them here as key/value pairs. If no `kid` is present in header or no `kid` provided when signing, then the default signing key will be used. If the default key should also be mapped to a key ID, be sure to add it here as well.
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
	 * @param Token $token Token instance with JWT claims.
	 * @param string|null $kid Key ID to include in header. The given key ID *must* map to a key in the key map.
	 * @throws SignerNotFoundException
	 * @throws TokenEncodingException
	 * @return string
	 */
	public function encode(Token $token, ?string $kid = null): string
	{
		$signer = $this->getSigner($kid);

		$header = [
			"algo" => $signer->getAlgorithm(),
			"typ" => "JWT"
		];

		if( $kid !== null ) {
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
	 * @param string $jwt The encoded JWT string.
	 * @throws InvalidTokenException
	 * @throws SignerNotFoundException
	 * @throws SignatureMismatchException
	 * @throws ExpiredTokenException
	 * @throws TokenNotReadyException
	 * @return Token
	 */
	public function decode(string $jwt): Token
	{
		$parts = \explode(".", $jwt);

		if( \count($parts) !== 3 ){
			throw new InvalidTokenException("Invalid number of token parts.");
		}

		[$header, $payload, $signature] = $parts;

		/** @var object{algo:string,typ:string,kid:mixed} $decoded_header */
		$decoded_header = \json_decode($this->base64UrlDecode($header));

		if( \json_last_error() !== JSON_ERROR_NONE ){
			throw new InvalidTokenException("Token header could not be JSON decoded.");
		}

		$signer = $this->getSigner($decoded_header->kid ?? null);

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

		if( isset($decoded_payload->exp) ){

			if( !\is_int($decoded_payload->exp) ){
				throw new InvalidTokenException("Expiration (exp) claim is not correctly formatted.");
			}

			if( $decoded_payload->exp < ($timestamp + $this->leeway) ){
				throw new ExpiredTokenException("The token has expired.");
			}
		}

		if( isset($decoded_payload->nbf) ){

			if( !\is_int($decoded_payload->nbf) ){
				throw new InvalidTokenException("Not before (nbf) claim is not correctly formatted.");
			}

			if( $decoded_payload->nbf > ($timestamp - $this->leeway) ){
				throw new TokenNotReadyException("The token is not ready to be accepted yet.");
			}
		}

		return new Token((array) $decoded_payload);
	}

	/**
	 * Get the SignerInterface instance to use.
	 *
	 * @param string|null $kid Get a specific signer by its key from the KeyMap as defined in the constructor. If null, default signer will be returned.
	 * @throws SignerNotFoundException
	 * @return SignerInterface
	 */
	private function getSigner(?string $kid = null): SignerInterface
	{
		if( $kid !== null ) {
			if( !isset($this->keyMap[$kid]) ){
				throw new SignerNotFoundException("No signer found for key ID.");
			}

			$signer = $this->keyMap[$kid];
		}
		else {
			$signer = $this->signer;
		}

		return $signer;
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