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

    /// <summary>
    /// Initializes a new instance of the <see cref="X25519Recipient"/> class with a public key.
    /// This constructor creates a recipient that can only be used for encryption.
    /// </summary>
    /// <param name="publicKey">The X25519 public key.</param>
    /// <exception cref="ArgumentNullException">Thrown when publicKey is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when publicKey has an invalid length.</exception>
    public X25519Recipient(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != X25519.KeySize) 
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        _publicKey = publicKey;
        _privateKey = null;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X25519Recipient"/> class with a public and private key pair.
    /// This constructor creates a recipient that can be used for both encryption and decryption.
    /// </summary>
    /// <param name="publicKey">The X25519 public key.</param>
    /// <param name="privateKey">The X25519 private key.</param>
    /// <exception cref="ArgumentNullException">Thrown when publicKey or privateKey is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when publicKey or privateKey has an invalid length.</exception>
    public X25519Recipient(byte[] publicKey, byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(privateKey);

        if (publicKey.Length != X25519.KeySize) 
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        if (privateKey.Length != X25519.KeySize) 
            throw new AgeKeyException($"Private key must be {X25519.KeySize} bytes");

        _publicKey = publicKey;
        _privateKey = privateKey;
    }

    /// <summary>
    /// Gets the recipient type.
    /// </summary>
    public string Type => "X25519";

    /// <summary>
    /// Creates a stanza for this recipient containing the wrapped file key.
    /// </summary>
    /// <param name="fileKey">The file key to wrap.</param>
    /// <returns>A stanza containing the wrapped file key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when fileKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when fileKey has an invalid length.</exception>
    public Stanza CreateStanza(byte[] fileKey)
    {
        ValidationUtils.ValidateFileKey(fileKey);

        // Generate an ephemeral key pair
        var (ephemeralPrivateKey, ephemeralPublicKey) = X25519.GenerateKeyPair();

        // Perform key agreement between the ephemeral private key and the recipient's public key
        var sharedSecret = X25519.KeyAgreement(ephemeralPrivateKey, _publicKey);

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = CombineKeys(ephemeralPublicKey, _publicKey);
        var wrappingKey = Hkdf.DeriveKey(
            sharedSecret, 
            salt, 
            HkdfInfoString, 
            DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);

        // Encrypt the file key with the wrapping key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        var wrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

        // Create the stanza
        var stanza = new Stanza(Type);
        stanza.Arguments.Add(Base64Utils.EncodeToString(ephemeralPublicKey));
        stanza.Body = wrappedKey;

        return stanza;
    }

    /// <summary>
    /// Unwraps a file key from a stanza.
    /// </summary>
    /// <param name="stanza">The stanza containing the wrapped file key.</param>
    /// <returns>The unwrapped file key, or null if this recipient cannot unwrap the key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when stanza is null.</exception>
    /// <exception cref="ArgumentException">Thrown when stanza has an invalid format.</exception>
    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 1);

        if (_privateKey is null) 
            return null; // Cannot unwrap without a private key

        // Extract the ephemeral public key and wrapped key
        var ephemeralPublicKey = Base64Utils.DecodeString(stanza.Arguments[0]);
        var wrappedKey = stanza.Body;

        // Perform key agreement between the recipient's private key and the ephemeral public key
        var sharedSecret = X25519.KeyAgreement(_privateKey, ephemeralPublicKey);

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = CombineKeys(ephemeralPublicKey, _publicKey);
        var wrappingKey = Hkdf.DeriveKey(
            sharedSecret, 
            salt, 
            HkdfInfoString, 
            DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);

        // Decrypt the wrapped key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        return DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
    }

    /// <summary>
    /// Creates a recipient from a public key.
    /// </summary>
    /// <param name="publicKey">The X25519 public key.</param>
    /// <returns>A new X25519Recipient that can only be used for encryption.</returns>
    /// <exception cref="ArgumentNullException">Thrown when publicKey is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when publicKey has an invalid length.</exception>
    public static X25519Recipient FromPublicKey(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != X25519.KeySize) 
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        return new X25519Recipient(publicKey);
    }

    /// <summary>
    /// Creates a recipient from a private key.
    /// </summary>
    /// <param name="privateKey">The X25519 private key.</param>
    /// <returns>A new X25519Recipient that can be used for both encryption and decryption.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKey is null.</exception>
    /// <exception cref="AgeKeyException">Thrown when privateKey has an invalid length.</exception>
    public static X25519Recipient FromPrivateKey(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        if (privateKey.Length != X25519.KeySize) 
            throw new AgeKeyException($"Private key must be {X25519.KeySize} bytes");

        var publicKey = X25519.GetPublicKeyFromPrivateKey(privateKey);
        return new X25519Recipient(publicKey, privateKey);
    }

    /// <summary>
    /// Combines two keys into a single byte array.
    /// </summary>
    /// <param name="key1">The first key.</param>
    /// <param name="key2">The second key.</param>
    /// <returns>A byte array containing both keys concatenated.</returns>
    private static byte[] CombineKeys(byte[] key1, byte[] key2)
    {
        var combined = new byte[key1.Length + key2.Length];
        Buffer.BlockCopy(key1, 0, combined, 0, key1.Length);
        Buffer.BlockCopy(key2, 0, combined, key1.Length, key2.Length);
        return combined;
    }
}
