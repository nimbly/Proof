<?php

namespace Nimbly\Proof;

/**
 * This exception is thrown when the signature of the JWT does not match with the computed signature.
 * If this exception is thrown, it is *very* likely that the JWT was either tampered with or the incorrect
 * signer is being used.
 *
 * In either case, DO NOT trust the JWT being sent.
 */
class SignatureMismatchException extends TokenDecodingException
{
}