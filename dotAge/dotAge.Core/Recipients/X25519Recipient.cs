using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using dotAge.Core.Crypto;
using dotAge.Core.Format;
using Curve25519.NetCore;

namespace dotAge.Core.Recipients
{
    /// <summary>
    /// Represents an X25519 recipient in the age encryption system.
    /// </summary>
    public class X25519Recipient : IRecipient
    {
        // The type of the recipient
        public string Type => "X25519";

        // The HKDF info string for X25519
        private const string HkdfInfoString = "age-encryption.org/v1/X25519";

        // The public key of the recipient
        private readonly byte[] _publicKey;

        // The private key of the recipient (optional)
        private readonly byte[] _privateKey;

        /// <summary>
        /// Validates a file key.
        /// </summary>
        /// <param name="fileKey">The file key to validate.</param>
        /// <exception cref="ArgumentException">Thrown when the file key is invalid.</exception>
        private static void ValidateFileKey(byte[] fileKey)
        {
            if (fileKey == null || fileKey.Length != dotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"File key must be {dotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(fileKey));
        }

        /// <summary>
        /// Validates a stanza.
        /// </summary>
        /// <param name="stanza">The stanza to validate.</param>
        /// <exception cref="ArgumentNullException">Thrown when the stanza is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the stanza is invalid.</exception>
        private void ValidateStanza(Stanza stanza)
        {
            if (stanza == null)
                throw new ArgumentNullException(nameof(stanza));

            if (stanza.Type != Type)
                throw new ArgumentException($"Stanza type must be {Type}", nameof(stanza));

            if (stanza.Arguments.Count != 1)
                throw new ArgumentException("Stanza must have exactly one argument", nameof(stanza));

            // For decryption, we need at least one body line
            if (stanza.Body.Count < 1)
                throw new ArgumentException("Stanza must have at least one body line", nameof(stanza));
        }

        /// <summary>
        /// Creates a new X25519 recipient with the specified public key.
        /// </summary>
        /// <param name="publicKey">The public key of the recipient.</param>
        public X25519Recipient(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != X25519.KeySize)
                throw new ArgumentException($"Public key must be {X25519.KeySize} bytes", nameof(publicKey));

            _publicKey = publicKey;
            _privateKey = null;
        }

        /// <summary>
        /// Creates a new X25519 recipient with the specified public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key of the recipient.</param>
        /// <param name="privateKey">The private key of the recipient.</param>
        public X25519Recipient(byte[] publicKey, byte[] privateKey)
        {
            if (publicKey == null || publicKey.Length != X25519.KeySize)
                throw new ArgumentException($"Public key must be {X25519.KeySize} bytes", nameof(publicKey));

            if (privateKey == null || privateKey.Length != X25519.KeySize)
                throw new ArgumentException($"Private key must be {X25519.KeySize} bytes", nameof(privateKey));

            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <summary>
        /// Creates a new X25519 recipient from an encoded public key.
        /// </summary>
        /// <param name="encodedPublicKey">The encoded public key.</param>
        /// <returns>A new X25519 recipient.</returns>
        public static X25519Recipient FromEncodedPublicKey(string encodedPublicKey)
        {
            var publicKey = X25519.DecodePublicKey(encodedPublicKey);
            return new X25519Recipient(publicKey);
        }

        /// <summary>
        /// Creates a new X25519 recipient from an encoded private key.
        /// </summary>
        /// <param name="encodedPrivateKey">The encoded private key.</param>
        /// <returns>A new X25519 recipient.</returns>
        public static X25519Recipient FromEncodedPrivateKey(string encodedPrivateKey)
        {
            var privateKey = X25519.DecodePrivateKey(encodedPrivateKey);

            // Generate the public key from the private key using Curve25519.NetCore
            var curve25519 = new Curve25519.NetCore.Curve25519();
            var publicKey = curve25519.GetPublicKey(privateKey);

            return new X25519Recipient(publicKey, privateKey);
        }

        /// <summary>
        /// Creates a stanza for the recipient.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <returns>A stanza containing the wrapped file key.</returns>
        public Stanza CreateStanza(byte[] fileKey)
        {
            ValidateFileKey(fileKey);

            // Generate an ephemeral key pair
            var (ephemeralPrivateKey, ephemeralPublicKey) = X25519.GenerateKeyPair();

            // Perform key agreement between the ephemeral private key and the recipient's public key
            var sharedSecret = X25519.KeyAgreement(ephemeralPrivateKey, _publicKey);

            // Derive the wrapping key
            using var hkdf = new HMACSHA256(Encoding.ASCII.GetBytes(HkdfInfoString));
            hkdf.TransformBlock(ephemeralPublicKey, 0, ephemeralPublicKey.Length, null, 0);
            hkdf.TransformBlock(_publicKey, 0, _publicKey.Length, null, 0);
            hkdf.TransformFinalBlock(sharedSecret, 0, sharedSecret.Length);
            var wrappingKey = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.KeySize];
            Buffer.BlockCopy(hkdf.Hash, 0, wrappingKey, 0, wrappingKey.Length);

            // Encrypt the file key with the wrapping key
            var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            var wrappedKey = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

            // Create the stanza
            var stanza = new Stanza(Type);
            stanza.Arguments.Add(Convert.ToBase64String(ephemeralPublicKey));
            stanza.Body.Add(Convert.ToBase64String(wrappedKey));

            return stanza;
        }

        /// <summary>
        /// Unwraps a file key from a stanza.
        /// </summary>
        /// <param name="stanza">The stanza containing the wrapped file key.</param>
        /// <returns>The unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
        public byte[] UnwrapKey(Stanza stanza)
        {
            ValidateStanza(stanza);

            if (_privateKey == null)
                return null; // Cannot unwrap without a private key

            // Extract the ephemeral public key and wrapped key
            var ephemeralPublicKey = Convert.FromBase64String(stanza.Arguments[0]);
            var wrappedKey = Convert.FromBase64String(stanza.Body[0]);

            // Perform key agreement between the recipient's private key and the ephemeral public key
            var sharedSecret = X25519.KeyAgreement(_privateKey, ephemeralPublicKey);

            // Derive the wrapping key
            using var hkdf = new HMACSHA256(Encoding.ASCII.GetBytes(HkdfInfoString));
            hkdf.TransformBlock(ephemeralPublicKey, 0, ephemeralPublicKey.Length, null, 0);
            hkdf.TransformBlock(_publicKey, 0, _publicKey.Length, null, 0);
            hkdf.TransformFinalBlock(sharedSecret, 0, sharedSecret.Length);
            var wrappingKey = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.KeySize];
            Buffer.BlockCopy(hkdf.Hash, 0, wrappingKey, 0, wrappingKey.Length);

            // Decrypt the wrapped key
            var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            return dotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
        }

        /// <summary>
        /// Creates a stanza for the recipient asynchronously.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a stanza with the wrapped file key.</returns>
        public Task<Stanza> CreateStanzaAsync(byte[] fileKey, CancellationToken cancellationToken = default)
        {
            // Since X25519 operations are relatively fast and don't have async APIs,
            // we can just wrap the synchronous method in a Task
            return Task.Run(() => CreateStanza(fileKey), cancellationToken);
        }

        /// <summary>
        /// Unwraps a file key from a stanza asynchronously.
        /// </summary>
        /// <param name="stanza">The stanza containing the wrapped file key.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
        public Task<byte[]> UnwrapKeyAsync(Stanza stanza, CancellationToken cancellationToken = default)
        {
            // Since X25519 operations are relatively fast and don't have async APIs,
            // we can just wrap the synchronous method in a Task
            return Task.Run(() => UnwrapKey(stanza), cancellationToken);
        }
    }
}
