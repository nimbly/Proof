<?php

namespace Nimbly\Proof;

use Exception;

/**
 * This exception is thrown when a `kid` was passed in the JWT header but no such key exists in
 * the key map.
 */
class SignerNotFoundException extends Exception
{
}