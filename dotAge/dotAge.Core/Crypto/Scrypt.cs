using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;
using System.Runtime.CompilerServices;
using CryptSharp.Utility;

namespace DotAge.Core.Crypto;

/// <summary>
///     Scrypt key derivation function implementation.
///     Implements RFC 7914 specification, matching the age and rage implementations.
/// </summary>
public static class Scrypt
{
    private static readonly ILogger Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(Scrypt));

    public const int DefaultLogN = 18;
    public const int DefaultR = 8;
    public const int DefaultP = 1;
    public const int DefaultSaltSize = 16;
    public const int DefaultKeySize = 32;

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
            Logger.LogError(ex, "Scrypt key derivation failed");
            throw new AgeCryptoException("Scrypt key derivation failed", ex);
        }
    }

    public static byte[] DeriveKey(string password, byte[] salt, int keyLength = DefaultKeySize)
    {
        return DeriveKey(password, salt, DefaultLogN, DefaultR, DefaultP, keyLength);
    }

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