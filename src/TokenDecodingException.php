<?php

namespace Nimbly\Proof;

use Exception;

/**
 * This exception isn't thrown directly, but encompasses a class of exceptions.
 *
 * - InvalidTokenException
 * - ExpiredTokenException
 * - SignatureMismatchException
 * - TokenNotReadyException
 *
 */
class TokenDecodingException extends Exception
{
}