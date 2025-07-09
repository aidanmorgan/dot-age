using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;

namespace DotAge.Core.Recipients;

/// <summary>
///     Scrypt recipient implementation for age encryption with passphrase.
/// </summary>
public class ScryptRecipient : IRecipient
{
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
    }

    public ScryptRecipient(string passphrase, byte[] salt)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (salt == null || salt.Length == 0) throw new AgeKeyException("Salt cannot be null or empty");
        
        _passphrase = passphrase;
        _salt = salt;
        _workFactor = DefaultWorkFactor;
    }

    public ScryptRecipient(string passphrase, int workFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor) throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");
        
        _passphrase = passphrase;
        _salt = null;
        _workFactor = workFactor;
    }

    public string Type => "scrypt";

    public Stanza CreateStanza(byte[] fileKey)
    {
        ValidationUtils.ValidateFileKey(fileKey);

        // Generate a random salt (16 bytes as per age spec)
        var salt = RandomUtils.GenerateSalt(16);

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);

        // Derive the wrapping key from the passphrase and labeled salt
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, _workFactor);

        // Encrypt the file key with the wrapping key
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
        var wrappedKey = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

        // Create the stanza with two arguments: salt and work factor
        var stanza = new Stanza(Type);
        stanza.Arguments.Add(Base64Utils.EncodeToString(salt));
        stanza.Arguments.Add(_workFactor.ToString());
        stanza.Body = wrappedKey;

        return stanza;
    }

    public byte[]? UnwrapKey(Stanza stanza)
    {
        ValidationUtils.ValidateStanza(stanza, Type, 2);

        // Extract the salt and work factor
        var salt = Base64Utils.DecodeString(stanza.Arguments[0]);
        if (salt.Length != 16)
            return null; // Invalid salt length

        if (!int.TryParse(stanza.Arguments[1], out var workFactor))
            return null; // Invalid work factor

        if (workFactor > MaxWorkFactor || workFactor <= 0)
            return null; // Work factor too large or invalid

        var wrappedKey = stanza.Body;

        // Validate the encrypted file key size (16 bytes file key + 16 bytes tag = 32 bytes)
        if (wrappedKey.Length != 32)
            return null; // Invalid encrypted file key size

        // Create the salt with label prefix as per age spec
        var labeledSalt = new byte[ScryptLabel.Length + salt.Length];
        Encoding.ASCII.GetBytes(ScryptLabel).CopyTo(labeledSalt, 0);
        salt.CopyTo(labeledSalt, ScryptLabel.Length);

        // Derive the wrapping key from the passphrase and labeled salt
        var wrappingKey = Scrypt.DeriveKey(_passphrase, labeledSalt, workFactor);

        // Decrypt the wrapped key
        try
        {
            var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            return DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
        }
        catch (CryptographicException)
        {
            // Decryption failed, likely due to an incorrect passphrase
            return null;
        }
    }

    public static ScryptRecipient FromPassphrase(string passphrase, int workFactor = 18)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (workFactor < 1 || workFactor > MaxWorkFactor) throw new AgeKeyException($"Work factor must be between 1 and {MaxWorkFactor}");
        
        return new ScryptRecipient(passphrase, workFactor);
    }
}