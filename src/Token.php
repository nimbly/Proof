<?php

namespace Nimbly\Proof;

use JsonSerializable;

class Token implements JsonSerializable
{
	/**
	 * @param array<array-key,mixed> $claims Array of key/value pairs of JWT claims for token.
	 *
	 * For timestamp based public claims, be sure to use a Unix timestamp.
	 *
	 * * `exp` expiration date, in Unix timestamp format
	 * * `nbf` token not valid before before given date, in Unix timestamp format
	 * * `iat` date token issued at, in Unix timestamp format
	 */
	public function __construct(protected array $claims = [])
	{
	}

	/**
	 * Does token have a particular claim?
	 *
	 * @param string $claim
	 * @return boolean
	 */
	public function hasClaim(string $claim): bool
	{
		return \array_key_exists($claim, $this->claims);
	}

	/**
	 * Get a token claim.
	 *
	 * @param string $claim
	 * @return mixed
	 */
	public function getClaim(string $claim)
	{
		return $this->claims[$claim] ?? null;
	}

	/**
	 * Set a token claim.
	 *
	 * @param string $claim
	 * @param mixed $value
	 * @return void
	 */
	public function setClaim(string $claim, $value): void
	{
		$this->claims[$claim] = $value;
	}

	/**
	 * Get all claims as an array.
	 *
	 * @return array<array-key,mixed>
	 */
	public function toArray(): array
	{
		return $this->claims;
	}

	/**
	 * @inheritDoc
	 */
	public function jsonSerialize(): mixed
	{
		return $this->toArray();
	}
}