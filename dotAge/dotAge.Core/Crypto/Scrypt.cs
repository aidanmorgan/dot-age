using System.Security.Cryptography;
using System.Text;
using CryptSharp.Utility;
using DotAge.Core.Exceptions;

namespace DotAge.Core.Crypto;

public static class Scrypt
{
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
        if (workFactor <= 0)
            throw new AgeCryptoException("Work factor must be positive");
        if (r <= 0)
            throw new AgeCryptoException("R must be positive");
        if (p <= 0)
            throw new AgeCryptoException("P must be positive");
        if (keyLength <= 0)
            throw new AgeCryptoException("Key length must be positive");

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        // workFactor is already the log2 value (e.g., 18), so calculate N = 2^workFactor
        var n = 1 << workFactor;

        return SCrypt.ComputeDerivedKey(passwordBytes, salt, n, r, p, null, keyLength);
    }

}