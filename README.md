# Proof

A simple library capable of encoding, decoding, and validating signed JWTs.

## Requirements

* PHP 8.x
* OpenSSL PHP extension

## Installing

```bash
composer install nimbly/proof
```

## Usage overview

### Instantiate

Create a new `Proof` instance with your `SignerInterface` instance. The signer is responsible for signing your JWT to prevent tampering of your tokens. The `Proof` instance must be provided with your signing preference: `HmacSigner` or `KeypairSigner` (see **Signers** section for more information).

```php
$proof = new Proof(
    new KeypairSigner(
        Proof::ALGO_SHA256,
        \openssl_get_publickey($public_key_contents),
        \openssl_get_privatekey($private_key_contents)
    )
);
```

### Create a token

Create a new token with claims.

```php
$token = new Token([
    "iss" => "customer-data-service",
    "sub" => $user->id,
    "iat" => \time(),
    "exp" => \strtotime("+1 hour")
]);
```

### Encode the Token into a JWT string

Encode the `Token` instance into a JWT string.

```php
$jwt = $proof->encode($token);
```

### Decode the JWT string into a Token

Decode the JWT string into a `Token` instance.

```php
$token = $proof->decode($jwt);
```

## Tokens

A `Token` instance represents the payload of the JWT, where the meaningful application level data is stored. Things like the **sub**ject of the token, the **exp**iration timestamp, etc. This data is called a `claim`. For a full list of predefined public claims, see [https://www.iana.org/assignments/jwt/jwt.xhtml#claims](https://www.iana.org/assignments/jwt/jwt.xhtml#claims). You can also use your own custom claims to fit your needs.

### Creating a Token

When creating a `Token` instance, claims may be passed in through the constructor as a simple key => value pair.

```php
$token = new Token([
    "iss" => "customer-data-service",
    "sub" => $user->id,
    "custom_claim_foo" => "bar",
    "exp" => \strtotime("+1 hour")
])
```

Or you can set a claim on a token by calling the `setClaim` method.

```php
$token->setClaim("nbf", \strtotime("+1 week"));
```

### Encode a Token into a JWT

With a `Token` instance, you can encode it into a signed JWT by passing it into the `encode` method. You will be returned a signed JWT string.

```php
$jwt = $proof->encode($token);
```

### Exceptions when encoding

When encoding a Token, there are several failure points that will throw an exception:

* `TokenEncodingException` is thrown if the header or payload could not be properly JSON encoded.
* `SigningException` is thrown if there was a problem signing the JWT with the given `SignerInterface` instance.

### Decode a JWT into a Token

When you decode a JWT string it will also verify the signature and check the expiration (`exp`) and "not before" (`nbf`) claims (if present). If successful, you will receive a `Token` instance back loaded with the claims from the payload of the JWT.

```php
$token = $proof->decode($jwt);
```

You can get a claim on a token by calling the `getClaim` method.

```php
$subject = $token->getClaim("sub");
```

You can check whether a claim exists or not by calling the `hasClaim` method.

```php
if( $token->hasClaim("sub") ){
    // Load User from DB
}
```

You can get all claims on the token by calling the `toArray` method.

```php
$claims = $token->toArray();
```

### Exceptions when decoding

When decoding a JWT, there are several failure points that will throw an exception:

* `InvalidTokenException` is thrown if the JWT cannot be decoded due to being malformed or containing invalid JSON.
* `SignatureMismatchException` is thrown if the signature does not match.
* `ExpiredTokenException` is thrown if the token's `exp` claim is expired.
* `TokenNotReadyException` is thrown if the token's `nbf` claim is not ready (i.e. the timestamp is still in the future.).

## Signers

You need a `SignerInterface` instance to do the signing and verifying of JWTs.

### HMAC

The `HmacSigner` uses a shared secret to sign messages and verify signatures. It is a less secure alternative than using a key pair, as the same secret value used to sign messages must be used in any other system or service that needs to verify that signature.

```php
$hmacSigner = new HmacSigner(
    Proof::ALGO_SHA256,
    $secretsManager->getSecret("jwt_signing_key")
);
```

When using a shared secret, remember that it should be considered *highly* sensitive data and, as such, should not be persisted in a code repository (public or private) or deployed within your application. If an unauthorized 3rd party is able to gain access to your shared secret, they will be able to create their own tokens which could lead to leakage of sensitive data of your users and systems. If you suspect your shared secret has been leaked, generate a new shared secret immediately.

### Key pair

The `KeypairSigner` is the preferred signing method as it is more secure than using the `HmacSigner`. The key pair signer relies on using a private and public key pair. The private key is used to sign the JWT however the public key can only be used to verify signatures.

The `KeypairSigner` relies on a private and/or a public key as an instance of `OpenSSLAsymmetricKey` available in PHP since version 4.0 with the `openssl` extension/module. You can load the keys using the `openssl_get_privatekey` and `openssl_get_publickey` PHP functions.

The private key is optional and only required if you need to sign new tokens. The public key is optional and only required if you need to verify signatures of tokens.

For example:

```php
$keypairSigner = new KeypairSigner(
    Proof::ALGO_SHA256,
    \openssl_get_publickey($secretsManager->getSecret("public_key")),
    \openssl_get_privatekey($secretsManager->getSecret("private_key"))
);
```

#### Generating a key pair

If you don't already have one, you can create a key pair using `openssl` found on most Linux systems.

```bash
openssl genrsa -des3 -out private.pem 2048
```

Using the private key file that was just created (`private.pem`), output a public key.

```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

You should now have two files called `private.pem` and `public.pem`. The `private.pem` file is your private key and can be used to sign your JWTs. The `public.pem` file is your public key and can *only* be used to validate signatures on your signed JWTs.

Separating private and public keys is especially useful in a distributed or microservice architecture where most services only need to validate a JWT but do not generate their own tokens. For those services you only need the public key.

When creating a key pair, remember that your **private key** should be considered *highly* sensitive data and, as such, should not be persisted in a code repository (public or private) or deployed within your application. If an unauthorized 3rd party is able to gain access to your private key, they will be able to create their own tokens which could lead to leakage of sensitive data of your users and systems. If you suspect your private key has been leaked, generate a new key pair immediately.

### Custom signers

If you would like to implement your own custom signing solution, a `Nimbly\Proof\SignerInterface` is provided and can be passed into the `Proof` constructor.

## PSR-15 Middleware

`Proof` ships with a PSR-15 middleware you can use in your HTTP applications that will validate a JWT from the `ServerRequestInterface` instance. If the JWT is valid, a `Nimbly\Proof\Token` attribute will be added to the `ServerRequestInterface` instance that contains the `Nimbly\Proof\Token` instance. The `Token` instance can be used in a further middleware that adds additional context to your request such as a `User` instance.

If the JWT is invalid, an exception will be thrown. This exception will need to be handled by your application as you see fit. The possible exceptions thrown are:

* `InvalidTokenException` is thrown if the JWT cannot be decoded due to being malformed or containing invalid JSON.
* `SignatureMismatchException` is thrown if the signature does not match.
* `ExpiredTokenException` is thrown if the token's `exp` claim is expired.
* `TokenNotReadyException` is thrown if the token's `nbf` claim is not ready (i.e. the timestamp is still in the future.).

The middleware defaults to looking for the JWT in the `Authorization` HTTP header with a `Bearer` scheme. For example:

```http
Authorization: Bearer eyJhbGdvIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOjEyMzR9.zPBvMNQqDQldmAgMrcEwarbv28Dw2NEHvoC8PoLCNzY
```

You can override this behavior in the constructor by supplying the header name (case insensitive) and scheme (case sensitive). If there is no scheme, you can use a `null` or empty string value instead.

```php
new Nimbly\Proof\Middleware\ValidateJwtMiddleware(
    proof: $proof,
    header: "X-Custom-Header",
    scheme: null
);
```

### Decorating ServerRequestInterface instance

A common practice is to decorate your requests with additional attributes to add more context for your request handlers, such as a `User` entity that contains the user making the request. With the use of the `Nimbly\Proof\Middleware\ValidateJwtMiddleware` and your own middleware, this becomes a fairly trivial task.

```php
class AuthorizeUserMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $request->getAttribute(Nimbly\Proof\Token::class);

        if( empty($token) || $token->hasClaim("sub") === false ){
            throw new UnauthorizedHttpException("Bearer", "Please login to continue.");
        }

        $user = App\Models\User::find($token->getClaim("sub"));

        if( empty($user) ){
            throw new UnauthorizedHttpException("Bearer", "Please login to continue.");
        }

        $request = $request->withAttribute(App\Models\User::class, $user);

        return $handler->handle($request);
    }
}
```

In this example, each request that requires a user account has had that `User` instance attached to the `ServerRequestInteface` instance.