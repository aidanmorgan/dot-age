using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Utils;

namespace DotAge.Core.Recipients;

/// <summary>
///     Scrypt identity implementation for age decryption with passphrase.
/// </summary>
public class ScryptIdentity : IRecipient
{
    private const int DefaultMaxWorkFactor = 22;
    private const string ScryptLabel = "age-encryption.org/v1/scrypt";
    private readonly string _passphrase;
    private readonly int _maxWorkFactor;

    public ScryptIdentity(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        _passphrase = passphrase;
        _maxWorkFactor = DefaultMaxWorkFactor;
    }

    public ScryptIdentity(string passphrase, int maxWorkFactor)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > 30) throw new AgeKeyException("Max work factor must be between 1 and 30");
        
        _passphrase = passphrase;
        _maxWorkFactor = maxWorkFactor;
    }

    public string Type => "scrypt";

    public Stanza CreateStanza(byte[] fileKey)
    {
        // ScryptIdentity is used for decryption, not encryption
        throw new AgeCryptoException("ScryptIdentity cannot be used for encryption");
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

        if (workFactor > _maxWorkFactor || workFactor <= 0)
            return null; // Work factor too large or invalid

        var wrappedKey = stanza.Body;

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

    public static ScryptIdentity FromPassphrase(string passphrase, int maxWorkFactor = 22)
    {
        if (string.IsNullOrEmpty(passphrase)) throw new AgeKeyException("Passphrase cannot be null or empty");
        if (maxWorkFactor < 1 || maxWorkFactor > 30) throw new AgeKeyException("Max work factor must be between 1 and 30");
        
        return new ScryptIdentity(passphrase, maxWorkFactor);
    }
} 