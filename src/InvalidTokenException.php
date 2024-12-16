<?php

namespace Nimbly\Proof;

/**
 * This exception is thrown when something is fundamentally wrong with the JWT being decoded:
 *
 * - Token is not a JWT
 * - Token does not contain a signature
 * - Token (header or payload) does not contain valid JSON
 * - Expiration (exp) or Not Before (nbf) claims are not in Unix timestamp format
 */
class InvalidTokenException extends TokenDecodingException
{
}