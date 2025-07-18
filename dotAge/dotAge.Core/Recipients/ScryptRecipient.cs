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
///     Scrypt recipient implementation for age encryption with passphrase.
/// </summary>
public class ScryptRecipient : IRecipient
{
    private const int DefaultWorkFactor = 18;
    private const int MaxWorkFactor = 30; // Match Go's SetWorkFactor range (1-30)
    private const string ScryptLabel = "age-encryption.org/v1/scrypt";
    private const int WrappedKeySize = 32; // 16 bytes file key + 16 bytes tag

    private static readonly Lazy<ILogger<ScryptRecipient>> Logger = new(() =>
        LoggerFactory.CreateLogger<ScryptRecipient>());

    private readonly string _passphrase;
    private readonly int _workFactor;

    public ScryptRecipient(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");

        _passphrase = passphrase;
        _workFactor = DefaultWorkFactor;

        Logger.Value.LogTrace(
            "Created ScryptRecipient with passphrase (length: {PassphraseLength}), work factor: {WorkFactor}",
            passphrase.Length, _workFactor);
    }


    public ScryptRecipient(string passphrase, int workFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor)
            throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");

        _passphrase = passphrase;
        _workFactor = workFactor;

        Logger.Value.LogTrace(
            "Created ScryptRecipient with passphrase (length: {PassphraseLength}), work factor: {WorkFactor}",
            passphrase.Length, _workFactor);
    }

    public string Type => StanzaTypes.Scrypt;

    public Stanza CreateStanza(byte[] fileKey)
    {
        ValidationUtils.ValidateFileKey(fileKey);

        Logger.Value.LogTrace("Creating scrypt stanza for file key (length: {FileKeyLength} bytes)", fileKey.Length);

        // Generate a random salt as per age spec
        var salt = RandomUtils.GenerateSalt();
        Logger.Value.LogTrace("Generated random salt length: {SaltLength} bytes", salt.Length);

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);
        Logger.Value.LogTrace("Created labeled salt length: {LabeledSaltLength} bytes", labeledSalt.Length);

        // Derive the wrapping key from the passphrase and labeled salt
        Logger.Value.LogTrace("Calling Scrypt.DeriveKey with parameters:");
        Logger.Value.LogTrace("  Passphrase length: {PassphraseLength} characters", _passphrase.Length);
        Logger.Value.LogTrace("  Labeled salt length: {LabeledSaltLength} bytes", labeledSalt.Length);
        Logger.Value.LogTrace("  Work factor: {WorkFactor}", _workFactor);
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, _workFactor, Scrypt.DefaultR);
        Logger.Value.LogTrace("Derived wrapping key length: {WrappingKeyLength} bytes", wrappingKey.Length);

        // Encrypt the file key with the wrapping key
        var nonce = new byte[ChaCha20Poly1305.NonceSize];
        Logger.Value.LogTrace("Using zero nonce length: {NonceLength} bytes", nonce.Length);

        var wrappedKey = ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);
        Logger.Value.LogTrace("Wrapped file key length: {WrappedKeyLength} bytes", wrappedKey.Length);

        // Create the stanza with two arguments: salt and work factor
        var stanza = new Stanza(Type);
        stanza.Arguments.Add(Base64Utils.EncodeToString(salt));
        stanza.Arguments.Add(_workFactor.ToString());
        stanza.Body = wrappedKey;

        Logger.Value.LogTrace("Created stanza with {ArgumentCount} arguments and {BodyLength} bytes body",
            stanza.Arguments.Count, stanza.Body.Length);

        return stanza;
    }

    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 2);

        Logger.Value.LogTrace("Unwrapping key from stanza with {ArgumentCount} arguments and {BodyLength} bytes body",
            stanza.Arguments.Count, stanza.Body.Length);

        // Extract the salt and work factor
        var salt = Base64Utils.DecodeString(stanza.Arguments[0]);
        if (salt.Length != CryptoConstants.SaltSize)
        {
            Logger.Value.LogTrace("Invalid salt length: {SaltLength} (expected {ExpectedSaltSize})", salt.Length,
                CryptoConstants.SaltSize);
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
        Logger.Value.LogTrace("  Maximum allowed work factor: {MaxWorkFactor}", MaxWorkFactor);
        Logger.Value.LogTrace("  Work factor <= 0: {IsInvalid}", workFactor <= 0);
        Logger.Value.LogTrace("  Work factor > max: {IsTooLarge}", workFactor > MaxWorkFactor);

        if (workFactor <= 0)
        {
            Logger.Value.LogTrace("Work factor is invalid (<= 0): {WorkFactor}", workFactor);
            return null; // Invalid work factor
        }

        if (workFactor > MaxWorkFactor)
        {
            Logger.Value.LogTrace("Work factor exceeds maximum: {WorkFactor} > {MaxWorkFactor}", workFactor,
                MaxWorkFactor);
            return null; // Work factor too large
        }

        Logger.Value.LogTrace("Work factor validation passed: {WorkFactor} (max: {MaxWorkFactor})", workFactor,
            MaxWorkFactor);

        var wrappedKey = stanza.Body;
        Logger.Value.LogTrace("Extracted wrapped key length: {WrappedKeyLength} bytes", wrappedKey.Length);

        // Validate the encrypted file key size
        if (wrappedKey.Length != WrappedKeySize)
        {
            Logger.Value.LogTrace("Invalid wrapped key length: {WrappedKeyLength} (expected {ExpectedWrappedKeySize})",
                wrappedKey.Length, WrappedKeySize);
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
            var nonce = new byte[ChaCha20Poly1305.NonceSize];
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

    public static ScryptRecipient FromPassphrase(string passphrase, int workFactor = 18)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor)
            throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");

        Logger.Value.LogTrace("Creating ScryptRecipient from passphrase with work factor: {WorkFactor}", workFactor);
        return new ScryptRecipient(passphrase, workFactor);
    }
}