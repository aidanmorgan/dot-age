using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides X25519 key generation and key agreement functionality.
///     Implements RFC 7748 specification, matching the Go implementation.
/// </summary>
public class X25519
{
    private static readonly ILogger<X25519> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<X25519>();
    private static readonly KeyAgreementAlgorithm Algorithm = KeyAgreementAlgorithm.X25519;

    // X25519 key size in bytes
    public const int KeySize = 32;

    // X25519 public key prefix in age format
    public const string PublicKeyPrefix = "age1";

    // X25519 private key prefix in age format
    public const string PrivateKeyPrefix = "AGE-SECRET-KEY-";

    /// <summary>
    ///     Generates a new X25519 key pair.
    /// </summary>
    /// <returns>A tuple containing the private and public keys as byte arrays.</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        try
        {
            var keyCreationParams = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };
            
            using var key = Key.Create(Algorithm, keyCreationParams);
            var privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
            var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "X25519 key pair generation failed");
            throw new AgeKeyException("X25519 key pair generation failed", ex);
        }
    }

    /// <summary>
    ///     Performs X25519 key agreement between a private key and a public key.
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

        try
        {
            var keyCreationParams = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };

            var sharedSecretCreationParams = new SharedSecretCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };
            
            using var nsecPrivateKey = Key.Import(Algorithm, privateKey, KeyBlobFormat.RawPrivateKey, keyCreationParams);
            var nsecPublicKey = PublicKey.Import(Algorithm, publicKey, KeyBlobFormat.RawPublicKey);
            
            using var sharedSecret = Algorithm.Agree(nsecPrivateKey, nsecPublicKey, sharedSecretCreationParams);
            return sharedSecret?.Export(SharedSecretBlobFormat.RawSharedSecret) ?? throw new AgeKeyException("Key agreement failed to produce shared secret");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "X25519 key agreement failed");
            throw new AgeKeyException("X25519 key agreement failed", ex);
        }
    }

    /// <summary>
    ///     Derives the public key from a given private key.
    /// </summary>
    /// <param name="privateKey">The private key as a byte array.</param>
    /// <returns>The public key as a byte array.</returns>
    public static byte[] GetPublicKeyFromPrivateKey(byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != KeySize)
            throw new AgeKeyException($"Private key must be {KeySize} bytes");

        try
        {
            var keyCreationParams = new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            };
            
            using var nsecPrivateKey = Key.Import(Algorithm, privateKey, KeyBlobFormat.RawPrivateKey, keyCreationParams);
            return nsecPrivateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "X25519 public key derivation failed");
            throw new AgeKeyException("X25519 public key derivation failed", ex);
        }
    }
}