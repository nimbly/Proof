<?php

namespace Nimbly\Proof\Middleware;

use Nimbly\Proof\Proof;
use Nimbly\Proof\Token;
use Nimbly\Proof\ExpiredTokenException;
use Nimbly\Proof\InvalidTokenException;
use Nimbly\Proof\SignatureMismatchException;
use Nimbly\Proof\TokenNotReadyException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ValidateJwtMiddleware implements MiddlewareInterface
{
	public function __construct(
		protected Proof $proof,
		protected string $header = "Authorization",
		protected ?string $scheme = "Bearer")
	{
	}

	/**
	 * @inheritDoc
	 * @throws InvalidTokenException
	 * @throws SignatureMismatchException
	 * @throws ExpiredTokenException
	 * @throws TokenNotReadyException
	 */
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
	{
		$bearer_token = $this->getBearerToken($request->getHeaderLine($this->header), $this->scheme);

		if( $bearer_token ){
			$request = $request->withAttribute(
				Token::class,
				$this->proof->decode($bearer_token)
			);
		}

		return $handler->handle($request);
	}

	/**
	 * Extract the Bearer token (if any) from the Authorization header content.
	 *
	 * @param string $authorization_header
	 * @param string|null $scheme
	 * @return string|null
	 */
	private function getBearerToken(string $authorization_header, ?string $scheme = "Bearer"): ?string
	{
		$b64encoded = "[0-9a-zA-Z_\+\=\-\/]+";

		$pattern = \sprintf(
			"/^%s(%s\.%s\.%s)$/i",
			$scheme ? ($scheme . " ") : "",
			$b64encoded,
			$b64encoded,
			$b64encoded
		);

		if( \preg_match($pattern, $authorization_header, $match) ){
			return $match[1];
		}

		return null;
	}
}