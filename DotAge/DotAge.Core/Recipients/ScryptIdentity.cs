using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using ChaCha20Poly1305 = DotAge.Core.Crypto.ChaCha20Poly1305;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Recipients;

/// <summary>
///     Scrypt identity implementation for age decryption with passphrase.
/// </summary>
public class ScryptIdentity : IRecipient
{
    private const int DefaultMaxWorkFactor = 22; // Default max work factor for decryption
    private const int MaxWorkFactor = 30; // Match Go's SetWorkFactor range (1-30)
    private const string ScryptLabel = "age-encryption.org/v1/scrypt";

    private static readonly Lazy<ILogger<ScryptIdentity>> Logger = new(() =>
        LoggerFactory.CreateLogger<ScryptIdentity>());

    private readonly int _maxWorkFactor;

    private readonly string _passphrase;

    public ScryptIdentity(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");

        _passphrase = passphrase;
        _maxWorkFactor = DefaultMaxWorkFactor;

        Logger.Value.LogTrace(
            "Created ScryptIdentity with passphrase (length: {PassphraseLength}), max work factor: {MaxWorkFactor}",
            passphrase.Length, _maxWorkFactor);
    }

    public ScryptIdentity(string passphrase, int maxWorkFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > MaxWorkFactor)
            throw new AgeKeyException($"Max work factor must be between 1 and {MaxWorkFactor}");

        _passphrase = passphrase;
        _maxWorkFactor = maxWorkFactor;

        Logger.Value.LogTrace(
            "Created ScryptIdentity with passphrase (length: {PassphraseLength}), max work factor: {MaxWorkFactor}",
            passphrase.Length, _maxWorkFactor);
    }

    public string Type => "scrypt";

    public Stanza CreateStanza(byte[] fileKey)
    {
        // ScryptIdentity is used for decryption, not encryption
        Logger.Value.LogTrace("ScryptIdentity cannot be used for encryption");
        throw new AgeCryptoException("ScryptIdentity cannot be used for encryption");
    }

    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 2);

        Logger.Value.LogTrace("=== SCRYPT IDENTITY UNWRAP START ===");
        Logger.Value.LogTrace("Input stanza:");
        Logger.Value.LogTrace("  Type: {Type}", stanza.Type);
        Logger.Value.LogTrace("  Arguments count: {ArgumentCount}", stanza.Arguments.Count);
        for (var i = 0; i < stanza.Arguments.Count; i++)
            Logger.Value.LogTrace("  Argument {Index}: '{Value}'", i, stanza.Arguments[i]);
        Logger.Value.LogTrace("  Body length: {BodyLength} bytes", stanza.Body.Length);

        Logger.Value.LogTrace("Unwrapping key from stanza with {ArgumentCount} arguments and {BodyLength} bytes body",
            stanza.Arguments.Count, stanza.Body.Length);

        // Extract the salt and work factor
        var salt = Base64Utils.DecodeString(stanza.Arguments[0]);
        if (salt.Length != 16)
        {
            Logger.Value.LogTrace("Invalid salt length: {SaltLength} (expected 16)", salt.Length);
            return null; // Invalid salt length
        }

        Logger.Value.LogTrace("Extracted salt length: {SaltLength} bytes", salt.Length);

        // Parse work factor with detailed logging
        Logger.Value.LogTrace("Parsing work factor from argument: '{WorkFactorString}'", stanza.Arguments[1]);
        if (!int.TryParse(stanza.Arguments[1], out var workFactor))
        {
            Logger.Value.LogTrace("Failed to parse work factor as integer: '{WorkFactorString}'", stanza.Arguments[1]);
            return null; // Invalid work factor
        }

        Logger.Value.LogTrace("Successfully parsed work factor: {WorkFactor}", workFactor);
        Logger.Value.LogTrace("Work factor validation:");
        Logger.Value.LogTrace("  Parsed work factor: {WorkFactor}", workFactor);
        Logger.Value.LogTrace("  Maximum allowed work factor: {MaxWorkFactor}", _maxWorkFactor);
        Logger.Value.LogTrace("  Work factor <= 0: {IsInvalid}", workFactor <= 0);
        Logger.Value.LogTrace("  Work factor > max: {IsTooLarge}", workFactor > _maxWorkFactor);

        if (workFactor <= 0)
        {
            Logger.Value.LogTrace("Work factor is invalid (<= 0): {WorkFactor}", workFactor);
            return null; // Invalid work factor
        }

        if (workFactor > _maxWorkFactor)
        {
            Logger.Value.LogTrace("Work factor exceeds maximum: {WorkFactor} > {MaxWorkFactor}", workFactor,
                _maxWorkFactor);
            return null; // Work factor too large
        }

        Logger.Value.LogTrace("Work factor validation passed: {WorkFactor} (max: {MaxWorkFactor})", workFactor,
            _maxWorkFactor);

        var wrappedKey = stanza.Body;
        Logger.Value.LogTrace("Extracted wrapped key length: {WrappedKeyLength} bytes", wrappedKey.Length);

        // Validate the encrypted file key size (16 bytes file key + 16 bytes tag = 32 bytes)
        if (wrappedKey.Length != 32)
        {
            Logger.Value.LogTrace("Invalid wrapped key length: {WrappedKeyLength} (expected 32)", wrappedKey.Length);
            return null; // Invalid encrypted file key size
        }

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);
        Logger.Value.LogTrace("Created labeled salt length: {LabeledSaltLength} bytes", labeledSalt.Length);

        // Derive the wrapping key from the passphrase and labeled salt
        Logger.Value.LogTrace("Calling Scrypt.DeriveKey with parameters:");
        Logger.Value.LogTrace("  Passphrase length: {PassphraseLength} characters", _passphrase.Length);
        Logger.Value.LogTrace("  Labeled salt length: {LabeledSaltLength} bytes", labeledSalt.Length);
        Logger.Value.LogTrace("  Work factor: {WorkFactor}", workFactor);
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, workFactor, Scrypt.DefaultR);
        Logger.Value.LogTrace("Derived wrapping key length: {WrappingKeyLength} bytes", wrappingKey.Length);

        // Decrypt the wrapped key
        try
        {
            var nonce = new byte[ChaCha20Poly1305.NonceSize]; // All zeros
            Logger.Value.LogTrace("Using zero nonce length: {NonceLength} bytes", nonce.Length);

            var unwrappedKey = ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
            Logger.Value.LogTrace("Successfully unwrapped file key length: {UnwrappedKeyLength} bytes",
                unwrappedKey.Length);

            return unwrappedKey;
        }
        catch (AgeCryptoException ex) when (ex.Message.Contains("authentication tag verification failed"))
        {
            Logger.Value.LogTrace("Decryption failed: {Error}", ex.Message);
            // Decryption failed, likely due to an incorrect passphrase
            throw new AgeDecryptionException("Failed to decrypt file key: authentication tag verification failed", ex);
        }
        catch (CryptographicException ex)
        {
            Logger.Value.LogTrace("Decryption failed: {Error}", ex.Message);
            // Decryption failed, likely due to an incorrect passphrase
            throw new AgeDecryptionException("Failed to decrypt file key: authentication tag verification failed", ex);
        }
    }

    public bool SupportsStanzaType(string stanzaType)
    {
        return stanzaType == Type;
    }

    public static ScryptIdentity FromPassphrase(string passphrase, int maxWorkFactor = 22)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > MaxWorkFactor)
            throw new AgeKeyException($"Max work factor must be between 1 and {MaxWorkFactor}");

        Logger.Value.LogTrace("Creating ScryptIdentity from passphrase with max work factor: {MaxWorkFactor}",
            maxWorkFactor);
        return new ScryptIdentity(passphrase, maxWorkFactor);
    }
}