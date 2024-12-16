<?php

namespace Nimbly\Proof;

/**
 * This expception is thrown when a JWT has expired based on its `exp` (expiration) claim.
 */
class ExpiredTokenException extends TokenDecodingException
{
}