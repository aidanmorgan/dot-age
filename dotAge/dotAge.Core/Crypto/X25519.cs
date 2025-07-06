using System;
using Curve25519.NetCore;

namespace dotAge.Core.Crypto
{
    /// <summary>
    /// Provides X25519 key generation and key agreement functionality.
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
        /// Generates a new X25519 key pair.
        /// </summary>
        /// <returns>A tuple containing the private and public keys as byte arrays.</returns>
        public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
        {
            // Use Curve25519.NetCore to generate a key pair
            var privateKey = new byte[KeySize];
            var publicKey = new byte[KeySize];

            // Generate random private key
            var random = new Random();
            random.NextBytes(privateKey);

            // Generate public key from private key
            var curve25519 = new Curve25519.NetCore.Curve25519();
            publicKey = curve25519.GetPublicKey(privateKey);

            return (privateKey, publicKey);
        }

        /// <summary>
        /// Performs X25519 key agreement between a private key and a public key.
        /// </summary>
        /// <param name="privateKey">The private key as a byte array.</param>
        /// <param name="publicKey">The public key as a byte array.</param>
        /// <returns>The shared secret as a byte array.</returns>
        public static byte[] KeyAgreement(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null || privateKey.Length != KeySize)
                throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));

            if (publicKey == null || publicKey.Length != KeySize)
                throw new ArgumentException($"Public key must be {KeySize} bytes", nameof(publicKey));

            // Use Curve25519.NetCore to perform key agreement
            var curve25519 = new Curve25519.NetCore.Curve25519();
            var sharedSecret = curve25519.GetSharedSecret(privateKey, publicKey);

            return sharedSecret;
        }

        /// <summary>
        /// Encodes a public key as an age recipient string.
        /// </summary>
        /// <param name="publicKey">The public key as a byte array.</param>
        /// <returns>The encoded public key as a string.</returns>
        public static string EncodePublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != KeySize)
                throw new ArgumentException($"Public key must be {KeySize} bytes", nameof(publicKey));

            // Encode the public key in Base64
            var base64 = Convert.ToBase64String(publicKey);

            // Return the encoded public key with the prefix
            return $"{PublicKeyPrefix}{base64}";
        }

        /// <summary>
        /// Decodes an age recipient string to a public key.
        /// </summary>
        /// <param name="encodedPublicKey">The encoded public key as a string.</param>
        /// <returns>The public key as a byte array.</returns>
        public static byte[] DecodePublicKey(string encodedPublicKey)
        {
            if (string.IsNullOrEmpty(encodedPublicKey))
                throw new ArgumentException("Encoded public key cannot be null or empty", nameof(encodedPublicKey));

            if (!encodedPublicKey.StartsWith(PublicKeyPrefix))
                throw new ArgumentException($"Encoded public key must start with {PublicKeyPrefix}", nameof(encodedPublicKey));

            // Remove the prefix
            var base64 = encodedPublicKey.Substring(PublicKeyPrefix.Length);

            // Decode the Base64 string
            var publicKey = Convert.FromBase64String(base64);

            if (publicKey.Length != KeySize)
                throw new ArgumentException($"Decoded public key must be {KeySize} bytes", nameof(encodedPublicKey));

            return publicKey;
        }

        /// <summary>
        /// Encodes a private key as an age secret key string.
        /// </summary>
        /// <param name="privateKey">The private key as a byte array.</param>
        /// <returns>The encoded private key as a string.</returns>
        public static string EncodePrivateKey(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length != KeySize)
                throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));

            // Encode the private key in Base64
            var base64 = Convert.ToBase64String(privateKey);

            // Return the encoded private key with the prefix
            return $"{PrivateKeyPrefix}{base64}";
        }

        /// <summary>
        /// Decodes an age secret key string to a private key.
        /// </summary>
        /// <param name="encodedPrivateKey">The encoded private key as a string.</param>
        /// <returns>The private key as a byte array.</returns>
        public static byte[] DecodePrivateKey(string encodedPrivateKey)
        {
            if (string.IsNullOrEmpty(encodedPrivateKey))
                throw new ArgumentException("Encoded private key cannot be null or empty", nameof(encodedPrivateKey));

            if (!encodedPrivateKey.StartsWith(PrivateKeyPrefix))
                throw new ArgumentException($"Encoded private key must start with {PrivateKeyPrefix}", nameof(encodedPrivateKey));

            // Remove the prefix
            var base64 = encodedPrivateKey.Substring(PrivateKeyPrefix.Length);

            // Decode the Base64 string
            var privateKey = Convert.FromBase64String(base64);

            if (privateKey.Length != KeySize)
                throw new ArgumentException($"Decoded private key must be {KeySize} bytes", nameof(encodedPrivateKey));

            return privateKey;
        }
    }
}
