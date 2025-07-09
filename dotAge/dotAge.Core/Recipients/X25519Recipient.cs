using System.Security.Cryptography;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;

namespace DotAge.Core.Recipients;

/// <summary>
///     X25519 recipient implementation for age encryption.
/// </summary>
public class X25519Recipient : IRecipient
{
    private const string HkdfInfoString = "age-encryption.org/v1/X25519";
    private readonly byte[] _publicKey;
    private readonly byte[]? _privateKey;

    public X25519Recipient(byte[] publicKey)
    {
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (publicKey.Length != X25519.KeySize) throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");
        _publicKey = publicKey;
        _privateKey = null;
    }

    public X25519Recipient(byte[] publicKey, byte[] privateKey)
    {
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (publicKey.Length != X25519.KeySize) throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");
        if (privateKey.Length != X25519.KeySize) throw new AgeKeyException($"Private key must be {X25519.KeySize} bytes");
        
        _publicKey = publicKey;
        _privateKey = privateKey;
    }

    public string Type => "X25519";

    public Stanza CreateStanza(byte[] fileKey)
    {
        ValidationUtils.ValidateFileKey(fileKey);

        // Generate an ephemeral key pair
        var (ephemeralPrivateKey, ephemeralPublicKey) = X25519.GenerateKeyPair();

        // Perform key agreement between the ephemeral private key and the recipient's public key
        var sharedSecret = X25519.KeyAgreement(ephemeralPrivateKey, _publicKey);

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = new byte[ephemeralPublicKey.Length + _publicKey.Length];
        Buffer.BlockCopy(ephemeralPublicKey, 0, salt, 0, ephemeralPublicKey.Length);
        Buffer.BlockCopy(_publicKey, 0, salt, ephemeralPublicKey.Length, _publicKey.Length);

        var wrappingKey = Hkdf.DeriveKey(sharedSecret, salt, HkdfInfoString, DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);

        // Encrypt the file key with the wrapping key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        var wrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

        // Create the stanza
        var stanza = new Stanza(Type);
        stanza.Arguments.Add(Base64Utils.EncodeToString(ephemeralPublicKey));
        stanza.Body = wrappedKey;

        return stanza;
    }

    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 1);

        if (_privateKey == null) return null; // Cannot unwrap without a private key

        // Extract the ephemeral public key and wrapped key
        var ephemeralPublicKey = Base64Utils.DecodeString(stanza.Arguments[0]);
        var wrappedKey = stanza.Body;

        // Perform key agreement between the recipient's private key and the ephemeral public key
        var sharedSecret = X25519.KeyAgreement(_privateKey, ephemeralPublicKey);

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = new byte[ephemeralPublicKey.Length + _publicKey.Length];
        Buffer.BlockCopy(ephemeralPublicKey, 0, salt, 0, ephemeralPublicKey.Length);
        Buffer.BlockCopy(_publicKey, 0, salt, ephemeralPublicKey.Length, _publicKey.Length);

        var wrappingKey = Hkdf.DeriveKey(sharedSecret, salt, HkdfInfoString, DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);

        // Decrypt the wrapped key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        return DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
    }

    public static X25519Recipient FromPublicKey(byte[] publicKey)
    {
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (publicKey.Length != X25519.KeySize) throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");
        return new X25519Recipient(publicKey);
    }

    public static X25519Recipient FromPrivateKey(byte[] privateKey)
    {
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != X25519.KeySize) throw new AgeKeyException($"Private key must be {X25519.KeySize} bytes");
        var publicKey = X25519.GetPublicKeyFromPrivateKey(privateKey);
        return new X25519Recipient(publicKey, privateKey);
    }
}