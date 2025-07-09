using System.Security.Cryptography;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides X25519 key generation and key agreement functionality using Curve25519.NetCore.
/// </summary>
public class X25519
{
    // X25519 key size in bytes
    public const int KeySize = 32;

    // X25519 public key prefix in age format
    public const string PublicKeyPrefix = "age1";

    // X25519 private key prefix in age format
    public const string PrivateKeyPrefix = "AGE-SECRET-KEY-";

    /// <summary>
    ///     Generates a new X25519 key pair using Curve25519.NetCore.
    /// </summary>
    /// <returns>A tuple containing the private and public keys as byte arrays.</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        // Use Curve25519.NetCore to generate a key pair
        var privateKey = new byte[KeySize];
        var publicKey = new byte[KeySize];

        // Generate random private key using cryptographically secure random number generator
        privateKey = RandomUtils.GenerateRandomBytes(KeySize);

        // Clamp the private key as per RFC 7748
        ClampPrivateKey(privateKey);

        // Generate public key from private key
        var curve25519 = new Curve25519.NetCore.Curve25519();
        publicKey = curve25519.GetPublicKey(privateKey);

        return (privateKey, publicKey);
    }

    /// <summary>
    ///     Performs X25519 key agreement between a private key and a public key using Curve25519.NetCore.
    /// </summary>
    /// <param name="privateKey">The private key as a byte array.</param>
    /// <param name="publicKey">The public key as a byte array.</param>
    /// <returns>The shared secret as a byte array.</returns>
    public static byte[] KeyAgreement(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null || privateKey.Length != KeySize)
            throw new AgeKeyException($"Private key must be {KeySize} bytes");

        if (publicKey == null || publicKey.Length != KeySize)
            throw new AgeKeyException($"Public key must be {KeySize} bytes");

        // Clamp the private key as per RFC 7748
        var clampedKey = new byte[KeySize];
        Buffer.BlockCopy(privateKey, 0, clampedKey, 0, KeySize);
        ClampPrivateKey(clampedKey);

        // Use Curve25519.NetCore for key agreement
        var curve25519 = new Curve25519.NetCore.Curve25519();
        var sharedSecret = curve25519.GetSharedSecret(clampedKey, publicKey);

        return sharedSecret;
    }

    /// <summary>
    ///     Derives the public key from a given private key using Curve25519.NetCore.
    /// </summary>
    /// <param name="privateKey">The private key as a byte array.</param>
    /// <returns>The public key as a byte array.</returns>
    public static byte[] GetPublicKeyFromPrivateKey(byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != KeySize)
            throw new AgeKeyException($"Private key must be {KeySize} bytes");
        ClampPrivateKey(privateKey);
        var curve25519 = new Curve25519.NetCore.Curve25519();
        return curve25519.GetPublicKey(privateKey);
    }

    /// <summary>
    ///     Clamps a private key as specified in RFC 7748.
    ///     This ensures the key is properly formatted for X25519 operations.
    /// </summary>
    /// <param name="privateKey">The private key to clamp (modified in place).</param>
    private static void ClampPrivateKey(byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != KeySize)
            throw new AgeKeyException($"Private key must be {KeySize} bytes");

        // Clamp the private key as per RFC 7748
        privateKey[0] &= 248; // Clear bits 0, 1, 2
        privateKey[31] &= 127; // Clear bit 255
        privateKey[31] |= 64; // Set bit 254
    }
}