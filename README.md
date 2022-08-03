# Proof

A simple JWT encoding and decoding library.

## Installing

```bash
composer install nimbly/proof
```

## Usage

### Initialize with your signer

The signer is responsible for signing your JWT to prevent tampering of your tokens. The `Proof` instance must be provided with your signing preference: `HmacSigner` or `KeypairSigner`.

```php
$proof = new Proof(
	new KeypairSigner(
		Proof::ALGO_SHA256,
		\file_get_contents(__DIR__ . "/public.pem"),
		\file_get_contents(__DIR__ . "/private.pem")
	)
);
```

### Create a token

Create a token with claims.

```php
$token = new Token([
	"sub" => "3f74ee01-7f0b-4e98-b2f7-245a07759e68",
	"iat" => \time(),
	"exp" => \strtotime("+1 hour")
]);
```

### Encode the token

Encode your `Token` instance into a JWT.

```php
$jwt = $proof->encode($token);
```

## Token

A `Token` instance represents the payload of the JWT, where the meaningful application level data is stored. Things like the **sub**ject of the token, the **exp**iration timestamp, etc. This data is called a `claim`.

### Getting a Token from a JWT

When you decode a JWT, you will receive a `Token` instance back.

```php
$token = $proof->decode($jwt);
```

You can get a claim on a token by calling the `getClaim` method.

```php
$not_before = $token->getClaim("nbf");
```

You can check whether a claim exists or not by called the `hasClaim` method.

```php
if( $token->hasClaim("nbf") ){
	// ...
}
```

You can get all claims on the token by calling the `toArray` method.

```php
$claims = $token->toArray();
```

### Creating a Token

When creating a `Token` instance, claims may be passed in through the constructor as a simple key => value pair.

```php
$token = new Token([
	"sub" => "3f74ee01-7f0b-4e98-b2f7-245a07759e68",
	"iss" => "customer-data-service",
	"exp" => 1596863306
])
```

Or you can set a claim on a token by calling the `setClaim` method.

```php
$token->setClaim("nbf", \strtotime("+1 week"));
```

### Convert a Token into a JWT

With a `Token` instance, you can convert it into a JWT by passing it into the `encode` method.

```php
$jwt = $proof->encode($token);
```

## Signers

You need a `SignerInterface` instance to do the signing and verifying of JWTs.

### HMAC

The `HmacSigner` uses a shared secret to sign messages and verify signatures. It is a less secure alternative than using a key pair, as the same secret value used to sign messages must be used in any other system or service that needs to verify that signature.

```php
$hmacSigner = new HmacSigner(
	Proof::ALGO_256,
	\getenv("jwt_signing_key")
);
```

### Key pair

The `KeypairSigner` is the preferred signing method as it is more secure than using the `HmacSigner`. The key pair signer relies on using a private and public key pair. The private key is used to sign the JWT however the public key can only be used to verify signatures.

```php
$keypairSigner = new KeypairSigner(
	Proof::ALGO_256,
	\getenv("public.pem"),
	\getenv("private.pem")
);
```

#### Generating a key pair

Create a private key with `openssl`.

```bash
openssl genrsa -des3 -out private.pem 2048
```

Using the private key that was just created, output a public key.

```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```