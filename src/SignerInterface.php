<?php

namespace Proof;

interface SignerInterface
{
	/**
	 * Get the JWT specific algorithm name.
	 *
	 * @return string
	 */
	public function getAlgorithm(): string;

	/**
	 * Is the given JWT algorithm name supported?
	 *
	 * @param string $algorithm
	 * @return boolean
	 */
	public function isAlgorithmSupported(string $algorithm): bool;

	/**
	 * Sign a message.
	 *
	 * @param string $message
	 * @return string
	 */
	public function sign(string $message): string;

	/**
	 * Verify signature of message.
	 *
	 * @param string $message
	 * @param string $signature
	 * @return boolean
	 */
	public function verify(string $message, string $signature): bool;
}