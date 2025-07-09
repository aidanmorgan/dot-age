# DotAge - .NET Implementation of the age Encryption System

This is a .NET implementation of the [age encryption system](https://age-encryption.org/), referencing the following
implementations:

- Go: [FiloSottile/age](https://github.com/FiloSottile/age/tree/v1.2.1)
- Java: [exceptionfactory/jagged](https://github.com/exceptionfactory/jagged)
- Dart: [Producement/dage](https://github.com/Producement/dage)

## Overview of age Encryption

Age is a simple, modern, and secure file encryption tool and format. It features:

- Small, well-defined API
- X25519 for key agreement
- ChaCha20-Poly1305 for encryption
- Scrypt for password-based encryption
- Stanza-based format

## Project Structure

- `DotAge.Core`: The core library implementing the age encryption system
- `DotAge.Cli`: Command-line interface for encryption/decryption
- `DotAge.KeyGen`: Command-line tool for key generation
- `DotAge.Tests`: Tests for the core library

## Testing

The integration tests in `DotAge.Tests` validate the DotAge implementation against the
reference [FiloSottile/age](https://github.com/FiloSottile/age) Golang implementation and [Rage](https://github.com/str4d/rage) rust implementation. To run these tests, you need to have the FiloSottile/age implementation and str4d/rage binaries installed.

There is a stress test that can be run that will run random permutations of random data, you can run this by running `RUN_STRESS_TESTS=true dotnet test DotAge/DotAge.Tests/DotAge.Tests.csproj --filter "FullyQualifiedName~StressInteroperabilityTests"`

For the passphrase tests to work, you will need a version of [expect](https://linux.die.net/man/1/expect) installed to be able to handle the terminal

## Features

- X25519 key generation and key agreement
- ChaCha20-Poly1305 encryption/decryption
- Scrypt key derivation
- Age file format handling
- X25519 recipients (asymmetric encryption)
- Scrypt recipients (password-based encryption)
- Stream-based encryption/decryption for efficient handling of large files

## Usage

### Encrypting with X25519

```csharp
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using System.Text;

// Generate a key pair
var (privateKey, publicKey) = X25519.GenerateKeyPair();

// Create an Age instance
var age = new Age();

// Add a recipient
var recipient = new X25519Recipient(publicKey);
age.AddRecipient(recipient);

// Encrypt a file
age.EncryptFile("plaintext.txt", "ciphertext.age");

// Encrypt data
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, World!");
byte[] ciphertext = age.Encrypt(plaintext);
```

### Decrypting with X25519

```csharp
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;

// Create an Age instance
var age = new Age();

// Add an identity (requires both public and private keys)
var identity = new X25519Recipient(publicKey, privateKey);
age.AddIdentity(identity);

// Decrypt a file
age.DecryptFile("ciphertext.age", "plaintext.txt");

// Decrypt data
byte[] decrypted = age.Decrypt(ciphertext);
```

### Working with Key Files

```csharp
using DotAge.Core.Utils;

// Parse a key file to get the keys
var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes("key.txt");

// Create recipient from public key
var recipient = new X25519Recipient(publicKeyBytes);

// Create identity from private key
var identity = X25519Recipient.FromPrivateKey(privateKeyBytes);
```

### Encrypting with a Passphrase

```csharp
using DotAge.Core;
using DotAge.Core.Recipients;

// Create an Age instance
var age = new Age();

// Add a recipient
var recipient = new ScryptRecipient("passphrase");
age.AddRecipient(recipient);

// Encrypt a file
age.EncryptFile("plaintext.txt", "ciphertext.age");

// Encrypt data
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, World!");
byte[] ciphertext = age.Encrypt(plaintext);
```

### Decrypting with a Passphrase

```csharp
using DotAge.Core;
using DotAge.Core.Recipients;

// Create an Age instance
var age = new Age();

// Add an identity
var identity = new ScryptIdentity("passphrase");
age.AddIdentity(identity);

// Decrypt a file
age.DecryptFile("ciphertext.age", "plaintext.txt");

// Decrypt data
byte[] decrypted = age.Decrypt(ciphertext);
```

### Multiple Recipients

```csharp
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;

var age = new Age();

// Add multiple X25519 recipients
var (privateKey1, publicKey1) = X25519.GenerateKeyPair();
var (privateKey2, publicKey2) = X25519.GenerateKeyPair();

age.AddRecipient(new X25519Recipient(publicKey1));
age.AddRecipient(new X25519Recipient(publicKey2));

// Add a passphrase recipient
age.AddRecipient(new ScryptRecipient("shared-passphrase"));

// Encrypt - any of the recipients can decrypt
byte[] ciphertext = age.Encrypt(plaintext);
```

### Key Generation

```csharp
using DotAge.Core.Crypto;
using DotAge.Core.Utils;

// Generate a new key pair
var (privateKey, publicKey) = X25519.GenerateKeyPair();

// Encode to age format
string privateKeyAge = KeyFileUtils.EncodeAgeSecretKey(privateKey);
string publicKeyAge = KeyFileUtils.EncodeAgePublicKey(publicKey);

// Decode from age format
byte[] decodedPrivateKey = KeyFileUtils.DecodeAgeSecretKey(privateKeyAge);
byte[] decodedPublicKey = KeyFileUtils.DecodeAgePublicKey(publicKeyAge);
```

## Known Limitations

- SSH recipients (RSA, Ed25519) are not yet implemented

## Implementation Details

- Uses System.Security.Cryptography.ChaCha20Poly1305 for encryption/decryption
- Uses Curve25519.NetCore for X25519 key generation and key agreement (with proper RFC 7748 key clamping)
- Includes a native Scrypt implementation that is thread-safe and provides async capabilities
- All cryptographic operations support both synchronous and asynchronous APIs

## Future Improvements

- Implement SSH recipients (RSA, Ed25519)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
