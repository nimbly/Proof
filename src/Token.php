<?php

namespace Nimbly\Proof;

use JsonSerializable;

class Token implements JsonSerializable
{
	/**
	 * Token constructor.
	 *
	 * @param array<string,mixed> $claims JWT claims for token.
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
	 * @return array<string,mixed>
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