using System;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Logging;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace DotAge.Core.Recipients;

/// <summary>
///     X25519 recipient for age encryption.
///     Implements the age X25519 recipient specification.
/// </summary>
public class X25519Recipient : IRecipient
{
    private static readonly ILogger<X25519Recipient> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<X25519Recipient>();

    public string Type => "X25519";

    private readonly byte[]? _privateKey;
    private readonly byte[] _publicKey;

    /// <summary>
    ///     Creates a new X25519Recipient from a public key.
    /// </summary>
    /// <param name="publicKey">The public key.</param>
    public X25519Recipient(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != X25519.KeySize)
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        _publicKey = publicKey;
        _privateKey = null;
    }

    /// <summary>
    ///     Creates a new X25519Recipient from a private key.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    public X25519Recipient(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null || privateKey.Length != X25519.KeySize)
            throw new AgeKeyException($"Private key must be {X25519.KeySize} bytes");

        if (publicKey == null || publicKey.Length != X25519.KeySize)
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    /// <summary>
    ///     Creates a stanza for encrypting a file key.
    /// </summary>
    /// <param name="fileKey">The file key to encrypt.</param>
    /// <returns>The stanza containing the encrypted file key.</returns>
    public Stanza CreateStanza(byte[] fileKey)
    {
        if (fileKey == null || fileKey.Length != 16)
            throw new AgeCryptoException("File key must be 16 bytes");

        // Generate ephemeral key pair
        var (ephemeralPrivateKey, ephemeralPublicKey) = X25519.GenerateKeyPair();
        Logger.LogTrace("Ephemeral private key: {EphemeralPrivateKey}", BitConverter.ToString(ephemeralPrivateKey));
        Logger.LogTrace("Ephemeral public key: {EphemeralPublicKey}", BitConverter.ToString(ephemeralPublicKey));
        Logger.LogTrace("Recipient public key: {RecipientPublicKey}", BitConverter.ToString(_publicKey));

        // Perform key agreement
        var sharedSecret = X25519.KeyAgreement(ephemeralPrivateKey, _publicKey);
        Logger.LogTrace("Shared secret: {SharedSecret}", BitConverter.ToString(sharedSecret));

        // Create salt by combining ephemeral public key and recipient public key
        var salt = new byte[ephemeralPublicKey.Length + _publicKey.Length];
        Buffer.BlockCopy(ephemeralPublicKey, 0, salt, 0, ephemeralPublicKey.Length);
        Buffer.BlockCopy(_publicKey, 0, salt, ephemeralPublicKey.Length, _publicKey.Length);
        Logger.LogTrace("Salt: {Salt}", BitConverter.ToString(salt));

        // Derive wrapping key
        var wrappingKey = Hkdf.DeriveKey(sharedSecret, salt, "age-encryption.org/v1/X25519", 32);
        Logger.LogTrace("HKDF wrapping key: {WrappingKey}", BitConverter.ToString(wrappingKey));

        // Encrypt file key
        var nonce = new byte[12]; // All zeros
        Logger.LogTrace("Nonce: {Nonce}", BitConverter.ToString(nonce));
        Logger.LogTrace("File key (plaintext): {FileKey}", BitConverter.ToString(fileKey));
        var wrappedKey = ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);
        Logger.LogTrace("Wrapped key (ciphertext+tag): {WrappedKey}", BitConverter.ToString(wrappedKey));

        // Create stanza
        var arguments = new List<string> { Base64Utils.EncodeToString(ephemeralPublicKey) };
        var stanza = new Stanza("X25519", arguments, wrappedKey);

        return stanza;
    }

    public bool SupportsStanzaType(string stanzaType)
    {
        return string.Equals(stanzaType, "X25519", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    ///     Unwraps a file key from a stanza.
    /// </summary>
    /// <param name="stanza">The stanza containing the encrypted file key.</param>
    /// <returns>The decrypted file key, or null if unwrapping fails.</returns>
    public byte[]? UnwrapKey(Stanza stanza)
    {
        // Direct console output for debugging
        Console.WriteLine($"[DEBUG] X25519Recipient.UnwrapKey called with stanza type: '{stanza.Type}'");
        
        if (_privateKey == null)
        {
            Console.WriteLine("[DEBUG] No private key available");
            return null;
        }

        if (!SupportsStanzaType(stanza.Type))
        {
            Console.WriteLine($"[DEBUG] Stanza type '{stanza.Type}' does not match 'X25519', returning null");
            return null;
        }

        if (stanza.Arguments.Count != 1)
        {
            Console.WriteLine($"[DEBUG] Stanza has {stanza.Arguments.Count} arguments, expected 1, returning null");
            return null;
        }

        Console.WriteLine("[DEBUG] Stanza type matches, proceeding with decryption");
        Logger.LogTrace("UnwrapKey called with stanza type: '{StanzaType}', arguments: [{Arguments}]", stanza.Type, string.Join(", ", stanza.Arguments));

        try
        {
            // Decode ephemeral public key - standard age format uses base64 encoding
            byte[] ephemeralPublicKey;
            var keyArg = stanza.Arguments[0];
            Logger.LogTrace("Ephemeral public key (base64 string): '{KeyArg}' (length: {Length})", keyArg, keyArg.Length);
            try
            {
                ephemeralPublicKey = Base64Utils.DecodeString(keyArg);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Base64 decode failed for ephemeral public key: '{KeyArg}'", keyArg);
                // If base64 fails, try standard base64
                try
                {
                    ephemeralPublicKey = Convert.FromBase64String(keyArg);
                }
                catch (Exception ex2)
                {
                    Logger.LogError(ex2, "Standard base64 decode also failed for ephemeral public key: '{KeyArg}'", keyArg);
                    return null;
                }
            }
            Logger.LogTrace("Ephemeral public key (decoded bytes): {EphemeralPublicKey} (length: {Length})", BitConverter.ToString(ephemeralPublicKey), ephemeralPublicKey.Length);
            Logger.LogTrace("Own private key: {OwnPrivateKey}", BitConverter.ToString(_privateKey));
            Logger.LogTrace("Own public key: {OwnPublicKey}", BitConverter.ToString(_publicKey));

            if (ephemeralPublicKey.Length != X25519.KeySize)
            {
                Logger.LogError("Ephemeral public key decoded to {Length} bytes, expected {ExpectedLength}. Bytes: {Bytes}", ephemeralPublicKey.Length, X25519.KeySize, BitConverter.ToString(ephemeralPublicKey));
                return null;
            }

            // Perform key agreement
            var sharedSecret = X25519.KeyAgreement(_privateKey, ephemeralPublicKey);
            Logger.LogTrace("Shared secret: {SharedSecret}", BitConverter.ToString(sharedSecret));

            // Create salt
            var salt = new byte[ephemeralPublicKey.Length + _publicKey.Length];
            Buffer.BlockCopy(ephemeralPublicKey, 0, salt, 0, ephemeralPublicKey.Length);
            Buffer.BlockCopy(_publicKey, 0, salt, ephemeralPublicKey.Length, _publicKey.Length);
            Logger.LogTrace("Salt: {Salt}", BitConverter.ToString(salt));

            // Derive wrapping key
            var wrappingKey = Hkdf.DeriveKey(sharedSecret, salt, "age-encryption.org/v1/X25519", 32);
            Logger.LogTrace("HKDF wrapping key: {WrappingKey}", BitConverter.ToString(wrappingKey));

            // Decrypt file key
            var nonce = new byte[12]; // All zeros
            Logger.LogTrace("Nonce: {Nonce}", BitConverter.ToString(nonce));
            Logger.LogTrace("Wrapped key (ciphertext+tag): {WrappedKey}", BitConverter.ToString(stanza.Body));
            var unwrappedKey = ChaCha20Poly1305.Decrypt(wrappingKey, nonce, stanza.Body);
            Logger.LogTrace("Unwrapped file key (plaintext): {UnwrappedKey}", BitConverter.ToString(unwrappedKey));

            if (unwrappedKey.Length != 16)
                return null;

            return unwrappedKey;
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "Failed to unwrap X25519 key");
            return null;
        }
    }

    /// <summary>
    ///     Creates an X25519Recipient from a public key string.
    /// </summary>
    /// <param name="publicKeyString">The public key string.</param>
    /// <returns>The X25519Recipient.</returns>
    public static X25519Recipient FromPublicKey(string publicKeyString)
    {
        if (string.IsNullOrEmpty(publicKeyString))
            throw new AgeKeyException("Public key string cannot be null or empty");

        if (!publicKeyString.StartsWith(X25519.PublicKeyPrefix))
            throw new AgeKeyException($"Public key must start with {X25519.PublicKeyPrefix}");

        var (_, publicKey) = Bech32.Decode(publicKeyString);
        if (publicKey.Length != X25519.KeySize)
            throw new AgeKeyException($"Public key must be {X25519.KeySize} bytes");

        return new X25519Recipient(publicKey);
    }

    /// <summary>
    ///     Creates an X25519Recipient from a private key string.
    /// </summary>
    /// <param name="privateKeyString">The private key string.</param>
    /// <returns>The X25519Recipient.</returns>
    public static X25519Recipient FromPrivateKey(string privateKeyString)
    {
        if (string.IsNullOrEmpty(privateKeyString))
            throw new AgeKeyException("Private key string cannot be null or empty");

        if (!privateKeyString.StartsWith(X25519.PrivateKeyPrefix))
            throw new AgeKeyException($"Private key must start with {X25519.PrivateKeyPrefix}");

        var privateKey = KeyFileUtils.DecodeAgeSecretKey(privateKeyString);
        var publicKey = X25519.GetPublicKeyFromPrivateKey(privateKey);

        return new X25519Recipient(privateKey, publicKey);
    }

    /// <summary>
    ///     Combines two X25519Recipient instances.
    /// </summary>
    /// <param name="other">The other X25519Recipient.</param>
    /// <returns>A new X25519Recipient with combined keys.</returns>
    public X25519Recipient Combine(X25519Recipient other)
    {
        if (other == null)
            throw new ArgumentNullException(nameof(other));

        var combinedPrivateKey = _privateKey != null && other._privateKey != null
            ? XorKeys(_privateKey, other._privateKey)
            : null;

        var combinedPublicKey = XorKeys(_publicKey, other._publicKey);

        return combinedPrivateKey != null 
            ? new X25519Recipient(combinedPrivateKey, combinedPublicKey)
            : new X25519Recipient(combinedPublicKey);
    }

    private static byte[] XorKeys(byte[] key1, byte[] key2)
    {
        if (key1.Length != key2.Length)
            throw new AgeKeyException("Keys must have the same length");

        var combined = new byte[key1.Length];
        for (int i = 0; i < key1.Length; i++)
        {
            combined[i] = (byte)(key1[i] ^ key2[i]);
        }

        return combined;
    }
}
