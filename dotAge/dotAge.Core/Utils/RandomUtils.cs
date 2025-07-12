using System.Security.Cryptography;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for random number generation used across the codebase.
/// </summary>
public static class RandomUtils
{
    private static readonly Lazy<ILogger> Logger = new Lazy<ILogger>(() => DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(RandomUtils)));

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
    public static byte[] GenerateSalt(int saltLength = 16)
    {
        if (saltLength <= 0)
            throw new AgeCryptoException("Salt length must be positive");

        var salt = GenerateRandomBytes(saltLength);
        return salt;
    }
} 