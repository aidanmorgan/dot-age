using System.Security.Cryptography;
using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Crypto;

/// <summary>
///     ChaCha20-Poly1305 implementation for age encryption.
///     Implements RFC 8439 specification, matching the Go implementation.
/// </summary>
public static class ChaCha20Poly1305
{
    /// <summary>
    ///     The key size in bytes for ChaCha20-Poly1305.
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    ///     The nonce size in bytes for ChaCha20-Poly1305.
    /// </summary>
    public const int NonceSize = 12;

    /// <summary>
    ///     The authentication tag size in bytes for ChaCha20-Poly1305.
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    ///     The block size in bytes for ChaCha20-Poly1305.
    /// </summary>
    public const int BlockSize = 64;

    private static readonly Lazy<ILogger> Logger = new(() => LoggerFactory.CreateLogger(nameof(ChaCha20Poly1305)));
    private static readonly AeadAlgorithm Algorithm = AeadAlgorithm.ChaCha20Poly1305;

    /// <summary>
    ///     Encrypts data using ChaCha20-Poly1305.
    ///     This matches the Go implementation's aeadEncrypt function.
    /// </summary>
    /// <param name="key">The encryption key (32 bytes).</param>
    /// <param name="nonce">The nonce (12 bytes).</param>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The ciphertext (plaintext + 16-byte tag).</returns>
    public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
    {
        if (key.Length != KeySize)
            throw new AgeCryptoException($"Key must be {KeySize} bytes, got {key.Length}");
        if (nonce.Length != NonceSize)
            throw new AgeCryptoException($"Nonce must be {NonceSize} bytes, got {nonce.Length}");

        try
        {
            using var nsecKey = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
            var ciphertext = new byte[plaintext.Length + TagSize];
            Algorithm.Encrypt(nsecKey, nonce, ReadOnlySpan<byte>.Empty, plaintext, ciphertext);
            return ciphertext;
        }
        catch (Exception ex)
        {
            Logger.Value.LogError(ex, "ChaCha20Poly1305 encryption failed");
            throw new AgeCryptoException("Encryption failed", ex);
        }
    }

    /// <summary>
    ///     Decrypts data using ChaCha20-Poly1305.
    ///     This matches the Go implementation's aeadDecrypt function.
    /// </summary>
    /// <param name="key">The decryption key (32 bytes).</param>
    /// <param name="nonce">The nonce (12 bytes).</param>
    /// <param name="ciphertext">The ciphertext to decrypt (including tag).</param>
    /// <returns>The plaintext.</returns>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext)
    {
        if (key.Length != KeySize)
            throw new AgeCryptoException($"Key must be {KeySize} bytes, got {key.Length}");
        if (nonce.Length != NonceSize)
            throw new AgeCryptoException($"Nonce must be {NonceSize} bytes, got {nonce.Length}");
        if (ciphertext.Length < TagSize)
            throw new AgeCryptoException($"Ciphertext must be at least {TagSize} bytes, got {ciphertext.Length}");

        try
        {
            using var nsecKey = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
            var plaintext = new byte[ciphertext.Length - TagSize];
            var success = Algorithm.Decrypt(nsecKey, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext);
            if (!success) throw new AgeCryptoException("Authentication tag verification failed");
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            Logger.Value.LogError(ex, "ChaCha20Poly1305 decryption failed");
            throw new AgeCryptoException("Authentication tag verification failed", ex);
        }
        catch (Exception ex)
        {
            Logger.Value.LogError(ex, "ChaCha20Poly1305 decryption failed");
            throw new AgeCryptoException("Decryption failed", ex);
        }
    }

    /// <summary>
    ///     Decrypts data using ChaCha20-Poly1305 with explicit size validation.
    ///     This method follows the age specification by validating the expected plaintext size
    ///     before attempting decryption, similar to the golang and rust implementations.
    /// </summary>
    /// <param name="key">The decryption key (32 bytes).</param>
    /// <param name="nonce">The nonce (12 bytes).</param>
    /// <param name="ciphertext">The ciphertext to decrypt (including tag).</param>
    /// <param name="expectedPlaintextSize">The expected size of the plaintext in bytes.</param>
    /// <returns>The plaintext.</returns>
    /// <exception cref="AgeCryptoException">Thrown when the ciphertext size doesn't match the expected size.</exception>
    public static byte[] DecryptWithSizeValidation(byte[] key, byte[] nonce, byte[] ciphertext,
        int expectedPlaintextSize)
    {
        if (key.Length != KeySize)
            throw new AgeCryptoException($"Key must be {KeySize} bytes, got {key.Length}");
        if (nonce.Length != NonceSize)
            throw new AgeCryptoException($"Nonce must be {NonceSize} bytes, got {nonce.Length}");

        // Validate that the ciphertext size matches the expected plaintext size + tag size
        var expectedCiphertextSize = expectedPlaintextSize + TagSize;
        if (ciphertext.Length != expectedCiphertextSize)
            throw new AgeCryptoException(
                $"Ciphertext size mismatch: expected {expectedCiphertextSize} bytes, got {ciphertext.Length} bytes");

        try
        {
            using var nsecKey = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
            var plaintext = new byte[expectedPlaintextSize];
            var success = Algorithm.Decrypt(nsecKey, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext);
            if (!success) throw new AgeCryptoException("Authentication tag verification failed");
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            Logger.Value.LogError(ex, "ChaCha20Poly1305 decryption with size validation failed");
            throw new AgeCryptoException("Authentication tag verification failed", ex);
        }
        catch (Exception ex)
        {
            Logger.Value.LogError(ex, "ChaCha20Poly1305 decryption with size validation failed");
            throw new AgeCryptoException("Decryption failed", ex);
        }
    }
}