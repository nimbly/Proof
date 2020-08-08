<?php

use PHPUnit\Framework\TestCase;
use Proof\ExpiredTokenException;
use Proof\InvalidTokenException;
use Proof\Proof;
use Proof\SignatureMismatchException;
use Proof\Signer\HmacSigner;
use Proof\Token;
use Proof\TokenNotReadyException;

/**
 * @covers Proof\Proof
 * @covers Proof\Token
 * @covers Proof\Signer\HmacSigner
 */
class ProofTest extends TestCase
{
	public function test_encode_returns_jwt(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$jwt = $proof->encode(
			new Token(["sub" => 1234])
		);

		$this->assertEquals(
			"eyJhbGdvIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ==.eyJzdWIiOjEyMzR9.cmbeiUAq1k/poCcsCdcYetHPo7QzMEH/CpBApozs6RU=",
			$jwt
		);
	}

	public function test_decode_missing_parts_throws_invalid_token_exception(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$this->expectException(InvalidTokenException::class);

		$proof->decode(
			"header.payload"
		);
	}

	public function test_signature_verification_failure_throws_signature_mismatch_exception(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$jwt = $proof->encode(
			new Token([
				"sub" => "123456",
				"iat" => \time()
			])
		);

		[$header, $payload, $signature] = \explode(".", $jwt);

		// Modify the payload of the JWT
		$payload = \json_decode(\base64_decode($payload));
		$payload->sub = "456789";
		$payload = \base64_encode(\json_encode($payload));

		// Rebuild the JWT with modified payload
		$jwt = "{$header}.{$payload}.{$signature}";

		$this->expectException(SignatureMismatchException::class);

		$proof->decode($jwt);
	}

	public function test_malformed_json_payload_throws_invalid_token_exception(): void
	{
		$signer = new HmacSigner(Proof::ALGO_SHA256, "supersecret");

		$proof = new Proof($signer);

		$header = \base64_encode(\json_encode(["algo" => "HS256", "typ" => "JWT"]));
		$payload = \base64_encode("InvalidJsonPayload");

		$jwt = "{$header}.{$payload}";

		$signature = $signer->sign($jwt);

		$jwt .= "." . \base64_encode($signature);

		$this->expectException(InvalidTokenException::class);
		$proof->decode($jwt);
	}

	public function test_expired_token_throws_expired_token_exception(): void
	{
		$token = new Token([
			"exp" => \strtotime("-1 year")
		]);

		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$jwt = $proof->encode($token);

		$this->expectException(ExpiredTokenException::class);

		$proof->decode($jwt);
	}

	public function test_forthcoming_token_throws_token_not_ready_exception(): void
	{
		$token = new Token([
			"nbf" => \strtotime("+1 week")
		]);

		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$jwt = $proof->encode($token);

		$this->expectException(TokenNotReadyException::class);

		$proof->decode($jwt);
	}

	public function test_valid_jwt_returns_token_instance(): void
	{
		$token = new Token([
			"sub" => "12345",
			"exp" => \strtotime("+1 day"),
			"iat" => \time()
		]);

		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$t = $proof->decode(
			$proof->encode($token)
		);

		$this->assertInstanceOf(Token::class, $t);
		$this->assertEquals($token, $t);
	}
}