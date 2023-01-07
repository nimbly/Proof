<?php

use Nimbly\Capsule\Response;
use Nimbly\Capsule\ServerRequest;
use Nimbly\Proof\Middleware\ValidateJwtMiddleware;
use Nimbly\Proof\Proof;
use Nimbly\Proof\Signer\HmacSigner;
use Nimbly\Proof\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @covers Nimbly\Proof\Middleware\ValidateJwtMiddleware
 */
class ValidateJwtMiddlewareTest extends TestCase
{
	public function test_get_bearer_token_returns_token_string(): void
	{
		$validateJwtMiddleware = new ValidateJwtMiddleware(
			new Proof(
				new HmacSigner(Proof::ALGO_SHA256, "shared_secret")
			)
		);

		$reflectionClass = new ReflectionClass($validateJwtMiddleware);
		$reflectionMethod = $reflectionClass->getMethod("getBearerToken");
		$reflectionMethod->setAccessible(true);

		$jwt = $reflectionMethod->invoke($validateJwtMiddleware, "Bearer eyJhbGdvIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOjEyMzR9.zPBvMNQqDQldmAgMrcEwarbv28Dw2NEHvoC8PoLCNzY");

		$this->assertEquals(
			"eyJhbGdvIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOjEyMzR9.zPBvMNQqDQldmAgMrcEwarbv28Dw2NEHvoC8PoLCNzY",
			$jwt
		);
	}

	public function test_get_bearer_token_returns_null_if_no_match(): void
	{
		$validateJwtMiddleware = new ValidateJwtMiddleware(
			new Proof(
				new HmacSigner(Proof::ALGO_SHA256, "shared_secret")
			)
		);

		$reflectionClass = new ReflectionClass($validateJwtMiddleware);
		$reflectionMethod = $reflectionClass->getMethod("getBearerToken");
		$reflectionMethod->setAccessible(true);

		$jwt = $reflectionMethod->invoke($validateJwtMiddleware, "Basic adasdasdasd");

		$this->assertNull($jwt);
	}

	public function test_process_attaches_token_to_request(): void
	{
		$proof = new Proof(
			new HmacSigner(Proof::ALGO_SHA256, "shared_secret")
		);

		$token = new Token([
			"sub" => "0e8975bd-5999-4965-b71d-ae716c86e3da",
			"exp" => \strtotime("+30 day")
		]);

		$validateJwtMiddleware = new ValidateJwtMiddleware($proof);

		$response = $validateJwtMiddleware->process(
			new ServerRequest(method: "get", uri: "/foo", headers: ["Authorization" => "Bearer " . $proof->encode($token)]),
			new class implements RequestHandlerInterface {
				public function handle(ServerRequestInterface $request): ResponseInterface
				{
					return new Response(
						200,
						\json_encode([
							"token" => $request->getAttribute(Token::class)
						]),
						[
							"Content-Type" => "application/json"
						]
					);
				}
			}
		);

		$payload = \json_decode($response->getBody());

		$this->assertEquals(
			$token->getClaim("sub"),
			$payload->token->sub
		);

		$this->assertEquals(
			$token->getClaim("exp"),
			$payload->token->exp
		);
	}

	public function test_process_does_not_attach_token_to_request_if_missing(): void
	{
		$validateJwtMiddleware = new ValidateJwtMiddleware(
			new Proof(
				new HmacSigner(Proof::ALGO_SHA256, "shared_secret")
			)
		);

		$response = $validateJwtMiddleware->process(
			new ServerRequest(method: "get", uri: "/foo"),
			new class implements RequestHandlerInterface {
				public function handle(ServerRequestInterface $request): ResponseInterface
				{
					return new Response(
						200,
						\json_encode([
							"token" => $request->getAttribute(Token::class)
						]),
						[
							"Content-Type" => "application/json"
						]
					);
				}
			}
		);

		$payload = \json_decode($response->getBody());

		$this->assertNull($payload->token);
	}
}