using System.Security.Cryptography;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Recipients;

/// <summary>
///     X25519 recipient implementation for age encryption.
/// </summary>
public class X25519Recipient : IRecipient
{
    private static readonly ILogger<X25519Recipient> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<X25519Recipient>();

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
        
        Logger.LogTrace("Created X25519Recipient with public key: {PublicKeyHex}", BitConverter.ToString(publicKey));
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
        
        Logger.LogTrace("Created X25519Recipient with public key: {PublicKeyHex} and private key: {PrivateKeyHex}", 
            BitConverter.ToString(publicKey), BitConverter.ToString(privateKey));
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

        Logger.LogTrace("Creating X25519 stanza for file key: {FileKeyHex}", BitConverter.ToString(fileKey));

        // Generate an ephemeral key pair
        var (ephemeralPrivateKey, ephemeralPublicKey) = X25519.GenerateKeyPair();
        Logger.LogTrace("Generated ephemeral key pair - Private: {EphemeralPrivateKeyHex}, Public: {EphemeralPublicKeyHex}", 
            BitConverter.ToString(ephemeralPrivateKey), BitConverter.ToString(ephemeralPublicKey));

        // Perform key agreement between the ephemeral private key and the recipient's public key
        var sharedSecret = X25519.KeyAgreement(ephemeralPrivateKey, _publicKey);
        Logger.LogTrace("Generated shared secret: {SharedSecretHex}", BitConverter.ToString(sharedSecret));

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = CombineKeys(ephemeralPublicKey, _publicKey);
        Logger.LogTrace("Combined salt: {SaltHex}", BitConverter.ToString(salt));

        var wrappingKey = Hkdf.DeriveKey(
            sharedSecret, 
            salt, 
            HkdfInfoString, 
            DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);
        Logger.LogTrace("Derived wrapping key: {WrappingKeyHex}", BitConverter.ToString(wrappingKey));

        // Encrypt the file key with the wrapping key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        Logger.LogTrace("Using zero nonce: {NonceHex}", BitConverter.ToString(nonce));

        var wrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);
        Logger.LogTrace("Wrapped file key: {WrappedKeyHex}", BitConverter.ToString(wrappedKey));

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
        {
            Logger.LogTrace("Cannot unwrap key - no private key available");
            return null; // Cannot unwrap without a private key
        }

        Logger.LogTrace("Unwrapping key from stanza with {ArgumentCount} arguments and {BodyLength} bytes body", 
            stanza.Arguments.Count, stanza.Body.Length);

        // Extract the ephemeral public key and wrapped key
        var ephemeralPublicKey = Base64Utils.DecodeString(stanza.Arguments[0]);
        var wrappedKey = stanza.Body;

        Logger.LogTrace("Extracted ephemeral public key: {EphemeralPublicKeyHex}", BitConverter.ToString(ephemeralPublicKey));
        Logger.LogTrace("Extracted wrapped key: {WrappedKeyHex}", BitConverter.ToString(wrappedKey));

        // Perform key agreement between the recipient's private key and the ephemeral public key
        var sharedSecret = X25519.KeyAgreement(_privateKey, ephemeralPublicKey);
        Logger.LogTrace("Generated shared secret: {SharedSecretHex}", BitConverter.ToString(sharedSecret));

        // Derive the wrapping key using HKDF with salt = ephemeralPublicKey || recipientPublicKey
        var salt = CombineKeys(ephemeralPublicKey, _publicKey);
        Logger.LogTrace("Combined salt: {SaltHex}", BitConverter.ToString(salt));

        var wrappingKey = Hkdf.DeriveKey(
            sharedSecret, 
            salt, 
            HkdfInfoString, 
            DotAge.Core.Crypto.ChaCha20Poly1305.KeySize);
        Logger.LogTrace("Derived wrapping key: {WrappingKeyHex}", BitConverter.ToString(wrappingKey));

        // Decrypt the wrapped key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        Logger.LogTrace("Using zero nonce: {NonceHex}", BitConverter.ToString(nonce));

        var unwrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
        Logger.LogTrace("Unwrapped file key: {UnwrappedKeyHex}", BitConverter.ToString(unwrappedKey));

        return unwrappedKey;
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

        Logger.LogTrace("Creating X25519Recipient from public key: {PublicKeyHex}", BitConverter.ToString(publicKey));
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

        Logger.LogTrace("Creating X25519Recipient from private key: {PrivateKeyHex}", BitConverter.ToString(privateKey));

        var publicKey = X25519.GetPublicKeyFromPrivateKey(privateKey);
        Logger.LogTrace("Derived public key: {PublicKeyHex}", BitConverter.ToString(publicKey));

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
        Logger.LogTrace("Combining keys - Key1: {Key1Hex}, Key2: {Key2Hex}", 
            BitConverter.ToString(key1), BitConverter.ToString(key2));

        var combined = new byte[key1.Length + key2.Length];
        Buffer.BlockCopy(key1, 0, combined, 0, key1.Length);
        Buffer.BlockCopy(key2, 0, combined, key1.Length, key2.Length);

        Logger.LogTrace("Combined result: {CombinedHex}", BitConverter.ToString(combined));
        return combined;
    }
}
