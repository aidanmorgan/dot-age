using System.Security.Cryptography;
using System.Text;
using CryptSharp.Utility;
using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Crypto;

/// <summary>
///     Scrypt key derivation function implementation.
///     Implements RFC 7914 specification, matching the age and rage implementations.
/// </summary>
public static class Scrypt
{
    /// <summary>
    ///     Default log2(N) parameter for Scrypt (N = 2^18).
    /// </summary>
    public const int DefaultLogN = 18;

    /// <summary>
    ///     Default r parameter for Scrypt (memory cost).
    /// </summary>
    public const int DefaultR = 8;

    /// <summary>
    ///     Default p parameter for Scrypt (parallelization).
    /// </summary>
    public const int DefaultP = 1;

    /// <summary>
    ///     Default salt size in bytes.
    /// </summary>
    public const int DefaultSaltSize = CryptoConstants.SaltSize;

    /// <summary>
    ///     Default key size in bytes.
    /// </summary>
    public const int DefaultKeySize = 32;

    private static readonly Lazy<ILogger> Logger = new(() => LoggerFactory.CreateLogger(nameof(Scrypt)));

    /// <summary>
    ///     Derives a key using Scrypt with the specified parameters.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt to use for key derivation.</param>
    /// <param name="workFactor">The work factor (log2(N)).</param>
    /// <param name="r">The memory cost parameter.</param>
    /// <param name="p">The parallelization parameter.</param>
    /// <param name="keyLength">The length of the derived key in bytes.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(string password, byte[] salt, int workFactor = 18, int r = DefaultR,
        int p = DefaultP, int keyLength = DefaultKeySize)
    {
        if (string.IsNullOrEmpty(password))
            throw new AgeCryptoException("Password cannot be null or empty");
        if (salt == null || salt.Length == 0)
            throw new AgeCryptoException("Salt cannot be null or empty");
        if (workFactor < 1 || workFactor > 30)
            throw new AgeCryptoException("Work factor must be between 1 and 30");
        if (r < 1 || r > 255)
            throw new AgeCryptoException("R must be between 1 and 255");
        if (p < 1 || p > 255)
            throw new AgeCryptoException("P must be between 1 and 255");
        if (keyLength < 1)
            throw new AgeCryptoException("Key length must be positive");

        try
        {
            var n = 1 << workFactor; // N = 2^workFactor

            // Use CryptSharp's scrypt implementation which supports variable-length salts
            // This maintains full compatibility with age/rage implementations
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            return SCrypt.ComputeDerivedKey(passwordBytes, salt, n, r, p, null, keyLength);
        }
        catch (Exception ex)
        {
            Logger.Value.LogError(ex, "Scrypt key derivation failed");
            throw new AgeCryptoException("Scrypt key derivation failed", ex);
        }
    }

    /// <summary>
    ///     Derives a key using Scrypt with default parameters.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt to use for key derivation.</param>
    /// <param name="keyLength">The length of the derived key in bytes.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(string password, byte[] salt, int keyLength = DefaultKeySize)
    {
        return DeriveKey(password, salt, DefaultLogN, DefaultR, DefaultP, keyLength);
    }

    /// <summary>
    ///     Generates a random salt for Scrypt key derivation.
    /// </summary>
    /// <param name="saltSize">The size of the salt in bytes.</param>
    /// <returns>A random salt.</returns>
    public static byte[] GenerateSalt(int saltSize = DefaultSaltSize)
    {
        if (saltSize < 1)
            throw new AgeCryptoException("Salt size must be positive");

        var salt = new byte[saltSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        return salt;
    }
}