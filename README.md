# DotAge - .NET Implementation of the age Encryption System

This is a .NET implementation of the [age encryption system](https://age-encryption.org/), based on the following
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
- `DotAge.Tests`: Tests for the core library

## Testing

The integration tests in `DotAge.Tests` validate the DotAge implementation against the
reference [FiloSottile/age](https://github.com/FiloSottile/age) Golang implementation. To run these tests, you need to
have the FiloSottile/age implementation installed on your system.

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
// Create an Age instance
var age = new Age();

// Add an identity
var identity = new X25519Recipient(publicKey, privateKey);
age.AddIdentity(identity);

// Decrypt a file
age.DecryptFile("ciphertext.age", "plaintext.txt");

// Decrypt data
byte[] decrypted = age.Decrypt(ciphertext);
```

### Encrypting with a Passphrase

```csharp
// Create an Age instance
var age = new Age();

// Add a recipient
var recipient = new ScryptRecipient("passphrase");
age.AddRecipient(recipient);

// Encrypt a file
age.EncryptFile("plaintext.txt", "ciphertext.age");
```

### Decrypting with a Passphrase

```csharp
// Create an Age instance
var age = new Age();

// Add an identity
var identity = new ScryptRecipient("passphrase");
age.AddIdentity(identity);

// Decrypt a file
age.DecryptFile("ciphertext.age", "plaintext.txt");
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
- Add a CLI interface

## License

This project is licensed under the MIT License - see the LICENSE file for details.
