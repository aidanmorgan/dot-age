using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Recipients;

/// <summary>
///     Scrypt identity implementation for age decryption with passphrase.
/// </summary>
public class ScryptIdentity : IRecipient
{
    private static readonly ILogger<ScryptIdentity> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<ScryptIdentity>();

    private const int DefaultMaxWorkFactor = 22;
    private const string ScryptLabel = "age-encryption.org/v1/scrypt";
    private readonly string _passphrase;
    private readonly int _maxWorkFactor;

    public ScryptIdentity(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        _passphrase = passphrase;
        _maxWorkFactor = DefaultMaxWorkFactor;
        
        Logger.LogTrace("Created ScryptIdentity with passphrase (length: {PassphraseLength}), max work factor: {MaxWorkFactor}", 
            passphrase.Length, _maxWorkFactor);
    }

    public ScryptIdentity(string passphrase, int maxWorkFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > 30) throw new AgeKeyException("Max work factor must be between 1 and 30");
        
        _passphrase = passphrase;
        _maxWorkFactor = maxWorkFactor;
        Logger.LogTrace("Created ScryptIdentity with passphrase (length: {PassphraseLength}), max work factor: {MaxWorkFactor}", 
            passphrase.Length, _maxWorkFactor);
    }

    public string Type => "scrypt";

    public Stanza CreateStanza(byte[] fileKey)
    {
        // ScryptIdentity is used for decryption, not encryption
        Logger.LogTrace("ScryptIdentity cannot be used for encryption");
        throw new AgeCryptoException("ScryptIdentity cannot be used for encryption");
    }

    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 2);

        Logger.LogTrace("Unwrapping key from stanza with {ArgumentCount} arguments and {BodyLength} bytes body", 
            stanza.Arguments.Count, stanza.Body.Length);

        // Extract the salt and work factor
        var salt = Base64Utils.DecodeString(stanza.Arguments[0]);
        if (salt.Length != 16)
        {
            Logger.LogTrace("Invalid salt length: {SaltLength} (expected 16)", salt.Length);
            return null; // Invalid salt length
        }

        Logger.LogTrace("Extracted salt: {SaltHex}", BitConverter.ToString(salt));

        if (!int.TryParse(stanza.Arguments[1], out var workFactor))
        {
            Logger.LogTrace("Invalid work factor: {WorkFactorString}", stanza.Arguments[1]);
            return null; // Invalid work factor
        }

        if (workFactor > _maxWorkFactor || workFactor <= 0)
        {
            Logger.LogTrace("Work factor out of range: {WorkFactor} (max: {MaxWorkFactor})", workFactor, _maxWorkFactor);
            return null; // Work factor too large or invalid
        }

        Logger.LogTrace("Extracted work factor: {WorkFactor}", workFactor);

        var wrappedKey = stanza.Body;
        Logger.LogTrace("Extracted wrapped key: {WrappedKeyHex}", BitConverter.ToString(wrappedKey));

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);
        Logger.LogTrace("Created labeled salt: {LabeledSaltHex}", BitConverter.ToString(labeledSalt));

        // Derive the wrapping key from the passphrase and labeled salt
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, workFactor);
        Logger.LogTrace("Derived wrapping key: {WrappingKeyHex}", BitConverter.ToString(wrappingKey));

        // Decrypt the wrapped key
        try
        {
            var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            Logger.LogTrace("Using zero nonce: {NonceHex}", BitConverter.ToString(nonce));

            var unwrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
            Logger.LogTrace("Successfully unwrapped file key: {UnwrappedKeyHex}", BitConverter.ToString(unwrappedKey));

            return unwrappedKey;
        }
        catch (CryptographicException ex)
        {
            Logger.LogTrace("Decryption failed: {Error}", ex.Message);
            // Decryption failed, likely due to an incorrect passphrase
            return null;
        }
    }

    public static ScryptIdentity FromPassphrase(string passphrase, int maxWorkFactor = 22)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > 30) throw new AgeKeyException("Max work factor must be between 1 and 30");
        
        Logger.LogTrace("Creating ScryptIdentity from passphrase with max work factor: {MaxWorkFactor}", maxWorkFactor);
        return new ScryptIdentity(passphrase, maxWorkFactor);
    }
} 