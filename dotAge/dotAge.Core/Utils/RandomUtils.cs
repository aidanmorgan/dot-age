using System.Security.Cryptography;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for random number generation used across the codebase.
/// </summary>
public static class RandomUtils
{
    private static readonly Lazy<ILogger> Logger = new(() => LoggerFactory.CreateLogger(nameof(RandomUtils)));

    /// <summary>
    ///     Generates cryptographically secure random bytes.
    /// </summary>
    /// <param name="length">The length of the random bytes to generate.</param>
    /// <returns>A byte array containing random bytes.</returns>
    public static byte[] GenerateRandomBytes(int length)
    {
        if (length <= 0)
            throw new AgeCryptoException("Length must be positive");

        var bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        return bytes;
    }

    /// <summary>
    ///     Generates a random salt for cryptographic operations.
    /// </summary>
    /// <param name="saltLength">The length of the salt to generate.</param>
    /// <returns>A random salt as a byte array.</returns>
    public static byte[] GenerateSalt(int saltLength = CryptoConstants.SaltSize)
    {
        if (saltLength <= 0)
            throw new AgeCryptoException("Salt length must be positive");

        var salt = GenerateRandomBytes(saltLength);
        return salt;
    }
}