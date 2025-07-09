using System.Security.Cryptography;
using DotAge.Core.Exceptions;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides ChaCha20-Poly1305 encryption and decryption functionality.
/// </summary>
public static class ChaCha20Poly1305
{
    // ChaCha20-Poly1305 key size in bytes
    public const int KeySize = 32;

    // ChaCha20-Poly1305 nonce size in bytes
    public const int NonceSize = 12;

    // ChaCha20-Poly1305 tag size in bytes
    public const int TagSize = 16;

    /// <summary>
    ///     Encrypts data using ChaCha20-Poly1305.
    /// </summary>
    /// <param name="key">The key as a byte array.</param>
    /// <param name="nonce">The nonce as a byte array.</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="associatedData">Optional associated data for the AEAD construction.</param>
    /// <returns>The ciphertext as a byte array, including the authentication tag.</returns>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[]? associatedData = null)
    {
        if (key == null || key.Length != KeySize)
            throw new AgeCryptoException($"Key must be {KeySize} bytes");

        if (nonce == null || nonce.Length != NonceSize)
            throw new AgeCryptoException($"Nonce must be {NonceSize} bytes");

        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));

        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        // Combine ciphertext and tag
        var result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);

        return result;
    }

    /// <summary>
    ///     Decrypts data using ChaCha20-Poly1305.
    /// </summary>
    /// <param name="key">The key as a byte array.</param>
    /// <param name="nonce">The nonce as a byte array.</param>
    /// <param name="ciphertext">The ciphertext to decrypt, including the authentication tag.</param>
    /// <param name="associatedData">Optional associated data for the AEAD construction.</param>
    /// <returns>The plaintext as a byte array.</returns>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[]? associatedData = null)
    {
        if (key == null || key.Length != KeySize)
            throw new AgeCryptoException($"Key must be {KeySize} bytes");

        if (nonce == null || nonce.Length != NonceSize)
            throw new AgeCryptoException($"Nonce must be {NonceSize} bytes");

        if (ciphertext == null || ciphertext.Length < TagSize)
            throw new AgeCryptoException("Ciphertext must include the authentication tag");

        // Extract ciphertext and tag
        var actualCiphertext = new byte[ciphertext.Length - TagSize];
        var tag = new byte[TagSize];
        Buffer.BlockCopy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);
        Buffer.BlockCopy(ciphertext, actualCiphertext.Length, tag, 0, TagSize);

        var plaintext = new byte[actualCiphertext.Length];

        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        aead.Decrypt(nonce, actualCiphertext, tag, plaintext, associatedData);

        return plaintext;
    }

}