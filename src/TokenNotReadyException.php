<?php

namespace Nimbly\Proof;

/**
 * This exception is thrown when a JWT has an `nbf` (not before) claim and represents a date
 * at which a token becomes active or usable however that date is still in the future.
 */
class TokenNotReadyException extends TokenDecodingException
{
}