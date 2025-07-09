using System.Security.Cryptography;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides X25519 key generation and key agreement functionality using Curve25519.NetCore.
/// </summary>
public class X25519
{
    private static readonly ILogger<X25519> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<X25519>();

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
        Logger.LogTrace("Generated raw private key: {PrivateKeyHex}", BitConverter.ToString(privateKey));

        // Clamp the private key as per RFC 7748
        ClampPrivateKey(privateKey);
        Logger.LogTrace("Clamped private key: {ClampedPrivateKeyHex}", BitConverter.ToString(privateKey));

        // Generate public key from private key
        var curve25519 = new Curve25519.NetCore.Curve25519();
        publicKey = curve25519.GetPublicKey(privateKey);
        Logger.LogTrace("Generated public key: {PublicKeyHex}", BitConverter.ToString(publicKey));

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

        Logger.LogTrace("Performing X25519 key agreement");
        Logger.LogTrace("Private key: {PrivateKeyHex}", BitConverter.ToString(privateKey));
        Logger.LogTrace("Public key: {PublicKeyHex}", BitConverter.ToString(publicKey));

        // Clamp the private key as per RFC 7748
        var clampedKey = new byte[KeySize];
        Buffer.BlockCopy(privateKey, 0, clampedKey, 0, KeySize);
        ClampPrivateKey(clampedKey);
        Logger.LogTrace("Clamped private key for key agreement: {ClampedKeyHex}", BitConverter.ToString(clampedKey));

        // Use Curve25519.NetCore for key agreement
        var curve25519 = new Curve25519.NetCore.Curve25519();
        var sharedSecret = curve25519.GetSharedSecret(clampedKey, publicKey);
        Logger.LogTrace("Generated shared secret: {SharedSecretHex}", BitConverter.ToString(sharedSecret));

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

        Logger.LogTrace("Input private key: {PrivateKeyHex}", BitConverter.ToString(privateKey));

        ClampPrivateKey(privateKey);
        Logger.LogTrace("Clamped private key: {ClampedPrivateKeyHex}", BitConverter.ToString(privateKey));

        var curve25519 = new Curve25519.NetCore.Curve25519();
        var publicKey = curve25519.GetPublicKey(privateKey);
        Logger.LogTrace("Derived public key: {PublicKeyHex}", BitConverter.ToString(publicKey));

        return publicKey;
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

        Logger.LogTrace("Clamping private key according to RFC 7748");
        Logger.LogTrace("Original private key: {OriginalKeyHex}", BitConverter.ToString(privateKey));

        // Clamp the private key as per RFC 7748
        privateKey[0] &= 248; // Clear bits 0, 1, 2
        privateKey[31] &= 127; // Clear bit 255
        privateKey[31] |= 64; // Set bit 254

        Logger.LogTrace("Clamped private key: {ClampedKeyHex}", BitConverter.ToString(privateKey));
        Logger.LogTrace("Bit operations: byte[0] &= 248, byte[31] &= 127, byte[31] |= 64");
    }
}