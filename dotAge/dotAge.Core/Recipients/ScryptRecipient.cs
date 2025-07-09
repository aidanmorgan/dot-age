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
///     Scrypt recipient implementation for age encryption with passphrase.
/// </summary>
public class ScryptRecipient : IRecipient
{
    private static readonly ILogger<ScryptRecipient> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<ScryptRecipient>();

    private const int DefaultWorkFactor = 18;
    private const int MaxWorkFactor = 22;
    private const string ScryptLabel = "age-encryption.org/v1/scrypt";

    private readonly string _passphrase;
    private readonly byte[]? _salt;
    private readonly int _workFactor;

    public ScryptRecipient(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        
        _passphrase = passphrase;
        _salt = null;
        _workFactor = DefaultWorkFactor;
        
        Logger.LogTrace("Created ScryptRecipient with passphrase (length: {PassphraseLength}), work factor: {WorkFactor}", 
            passphrase.Length, _workFactor);
    }

    public ScryptRecipient(string passphrase, byte[] salt)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (salt == null || salt.Length == 0) throw new AgeKeyException("Salt cannot be null or empty");
        
        _passphrase = passphrase;
        _salt = salt;
        _workFactor = DefaultWorkFactor;
        
        Logger.LogTrace("Created ScryptRecipient with passphrase (length: {PassphraseLength}), salt: {SaltHex}, work factor: {WorkFactor}", 
            passphrase.Length, BitConverter.ToString(salt), _workFactor);
    }

    public ScryptRecipient(string passphrase, int workFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor) throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");
        
        _passphrase = passphrase;
        _salt = null;
        _workFactor = workFactor;
        
        Logger.LogTrace("Created ScryptRecipient with passphrase (length: {PassphraseLength}), work factor: {WorkFactor}", 
            passphrase.Length, _workFactor);
    }

    public string Type => "scrypt";

    public Stanza CreateStanza(byte[] fileKey)
    {
        ValidationUtils.ValidateFileKey(fileKey);

        Logger.LogTrace("Creating scrypt stanza for file key: {FileKeyHex}", BitConverter.ToString(fileKey));

        // Generate a random salt (16 bytes as per age spec)
        var salt = RandomUtils.GenerateSalt(16);
        Logger.LogTrace("Generated random salt: {SaltHex}", BitConverter.ToString(salt));

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);
        Logger.LogTrace("Created labeled salt: {LabeledSaltHex}", BitConverter.ToString(labeledSalt));

        // Derive the wrapping key from the passphrase and labeled salt
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, _workFactor);
        Logger.LogTrace("Derived wrapping key: {WrappingKeyHex}", BitConverter.ToString(wrappingKey));

        // Encrypt the file key with the wrapping key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        Logger.LogTrace("Using zero nonce: {NonceHex}", BitConverter.ToString(nonce));

        var wrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);
        Logger.LogTrace("Wrapped file key: {WrappedKeyHex}", BitConverter.ToString(wrappedKey));

        // Create the stanza with two arguments: salt and work factor
        var stanza = new Stanza(Type);
        stanza.Arguments.Add(Base64Utils.EncodeToString(salt));
        stanza.Arguments.Add(_workFactor.ToString());
        stanza.Body = wrappedKey;

        Logger.LogTrace("Created stanza with {ArgumentCount} arguments and {BodyLength} bytes body", 
            stanza.Arguments.Count, stanza.Body.Length);

        return stanza;
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

        if (workFactor > MaxWorkFactor || workFactor <= 0)
        {
            Logger.LogTrace("Work factor out of range: {WorkFactor} (max: {MaxWorkFactor})", workFactor, MaxWorkFactor);
            return null; // Work factor too large or invalid
        }

        Logger.LogTrace("Extracted work factor: {WorkFactor}", workFactor);

        var wrappedKey = stanza.Body;
        Logger.LogTrace("Extracted wrapped key: {WrappedKeyHex}", BitConverter.ToString(wrappedKey));

        // Validate the encrypted file key size (16 bytes file key + 16 bytes tag = 32 bytes)
        if (wrappedKey.Length != 32)
        {
            Logger.LogTrace("Invalid wrapped key length: {WrappedKeyLength} (expected 32)", wrappedKey.Length);
            return null; // Invalid encrypted file key size
        }

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

    public static ScryptRecipient FromPassphrase(string passphrase, int workFactor = 18)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor) throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");
        
        Logger.LogTrace("Creating ScryptRecipient from passphrase with work factor: {WorkFactor}", workFactor);
        return new ScryptRecipient(passphrase, workFactor);
    }
}