<?php

use PHPUnit\Framework\TestCase;
use Nimbly\Proof\ExpiredTokenException;
use Nimbly\Proof\InvalidTokenException;
use Nimbly\Proof\Proof;
use Nimbly\Proof\SignatureMismatchException;
use Nimbly\Proof\Signer\HmacSigner;
use Nimbly\Proof\Token;
use Nimbly\Proof\TokenEncodingException;
use Nimbly\Proof\TokenNotReadyException;

/**
 * @covers Nimbly\Proof\Proof
 */
class ProofTest extends TestCase
{
	public function test_default_leeway_value(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$reflectionClass = new ReflectionClass($proof);
		$reflectionProperty = $reflectionClass->getProperty("leeway");
		$reflectionProperty->setAccessible(true);

		$this->assertEquals(
			0,
			$reflectionProperty->getValue($proof)
		);
	}

	public function test_encode_returns_jwt(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$jwt = $proof->encode(
			new Token(["sub" => 1234])
		);

		$this->assertEquals(
			"eyJhbGdvIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOjEyMzR9.zPBvMNQqDQldmAgMrcEwarbv28Dw2NEHvoC8PoLCNzY",
			$jwt
		);
	}

	public function test_encode_bad_payload_throws_token_encoding_exception(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$token = new Token([
			"sub" => \fopen(__DIR__ . "/public.pem", "r")
		]);

		$this->expectException(TokenEncodingException::class);
		$proof->encode($token);
	}

	public function test_decode_missing_parts_throws_invalid_token_exception(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "supersecret")
		);

		$this->expectException(InvalidTokenException::class);

		$proof->decode("header.payload");
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

	public function test_jwt_with_base64_padding_can_still_match_signature(): void
	{
		$header = \base64_encode(\json_encode(["typ" => "JWT", "algo" => "sha256"]));
		$payload = \base64_encode(\json_encode(["sub" => "816d83f0-2f71-4457-bd8b-bb674bda093d", "act" => "e0cd89b9-3377-4850-a70a-a9fd2c698098", "email" => "test@example.com"]));

		$signer = new HmacSigner(Proof::ALGO_SHA384, "supersecret");

		$signature = \base64_encode($signer->sign($header . "." . $payload));

		$jwt = \sprintf(
			"%s.%s.%s",
			$header,
			$payload,
			$signature
		);

		$proof = new Proof($signer);
		$token = $proof->decode($jwt);

		$this->assertInstanceOf(Token::class, $token);
		$this->assertEquals("816d83f0-2f71-4457-bd8b-bb674bda093d", $token->getClaim("sub"));
		$this->assertEquals("e0cd89b9-3377-4850-a70a-a9fd2c698098", $token->getClaim("act"));
		$this->assertEquals("test@example.com", $token->getClaim("email"));
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