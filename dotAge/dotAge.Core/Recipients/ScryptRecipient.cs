using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using dotAge.Core.Crypto;
using dotAge.Core.Format;

namespace dotAge.Core.Recipients
{
    /// <summary>
    /// Represents a scrypt recipient in the age encryption system.
    /// </summary>
    public class ScryptRecipient : IRecipient
    {
        // The type of the recipient
        public string Type => "scrypt";

        // The passphrase of the recipient
        private readonly string _passphrase;

        // The salt of the recipient (for unwrapping)
        private readonly byte[] _salt;

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

            if (stanza.Body.Count < 1)
                throw new ArgumentException("Stanza must have at least one body line", nameof(stanza));
        }

        /// <summary>
        /// Creates a new scrypt recipient with the specified passphrase.
        /// </summary>
        /// <param name="passphrase">The passphrase of the recipient.</param>
        public ScryptRecipient(string passphrase)
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new ArgumentException("Passphrase cannot be null or empty", nameof(passphrase));

            _passphrase = passphrase;
            _salt = null;
        }

        /// <summary>
        /// Creates a new scrypt recipient with the specified passphrase and salt.
        /// </summary>
        /// <param name="passphrase">The passphrase of the recipient.</param>
        /// <param name="salt">The salt of the recipient.</param>
        public ScryptRecipient(string passphrase, byte[] salt)
        {
            if (string.IsNullOrEmpty(passphrase))
                throw new ArgumentException("Passphrase cannot be null or empty", nameof(passphrase));

            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty", nameof(salt));

            _passphrase = passphrase;
            _salt = salt;
        }

        /// <summary>
        /// Creates a stanza for the recipient.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <returns>A stanza containing the wrapped file key.</returns>
        public Stanza CreateStanza(byte[] fileKey)
        {
            ValidateFileKey(fileKey);

            // Generate a random salt
            var salt = Scrypt.GenerateSalt();

            // Derive the wrapping key from the passphrase and salt
            var wrappingKey = Scrypt.DeriveKey(_passphrase, salt);

            // Encrypt the file key with the wrapping key
            var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            var wrappedKey = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

            // Create the stanza
            var stanza = new Stanza(Type);
            stanza.Arguments.Add(Convert.ToBase64String(salt));
            stanza.Body.Add(Convert.ToBase64String(wrappedKey));

            return stanza;
        }

        /// <summary>
        /// Creates a stanza for the recipient asynchronously.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a stanza with the wrapped file key.</returns>
        public async Task<Stanza> CreateStanzaAsync(byte[] fileKey, CancellationToken cancellationToken = default)
        {
            ValidateFileKey(fileKey);

            // Generate a random salt
            var salt = await Scrypt.GenerateSaltAsync(Scrypt.DefaultSaltSize, cancellationToken);

            // Derive the wrapping key from the passphrase and salt
            var wrappingKey = await Scrypt.DeriveKeyAsync(_passphrase, salt, cancellationToken: cancellationToken);

            // Encrypt the file key with the wrapping key
            var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
            var wrappedKey = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(wrappingKey, nonce, fileKey);

            // Create the stanza
            var stanza = new Stanza(Type);
            stanza.Arguments.Add(Convert.ToBase64String(salt));
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

            // Extract the salt and wrapped key
            var salt = _salt ?? Convert.FromBase64String(stanza.Arguments[0]);
            var wrappedKey = Convert.FromBase64String(stanza.Body[0]);

            // Derive the wrapping key from the passphrase and salt
            var wrappingKey = Scrypt.DeriveKey(_passphrase, salt);

            // Decrypt the wrapped key
            try
            {
                var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
                return dotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
            }
            catch (CryptographicException)
            {
                // Decryption failed, likely due to an incorrect passphrase
                return null;
            }
        }

        /// <summary>
        /// Unwraps a file key from a stanza asynchronously.
        /// </summary>
        /// <param name="stanza">The stanza containing the wrapped file key.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
        public async Task<byte[]> UnwrapKeyAsync(Stanza stanza, CancellationToken cancellationToken = default)
        {
            ValidateStanza(stanza);

            // Extract the salt and wrapped key
            var salt = _salt ?? Convert.FromBase64String(stanza.Arguments[0]);
            var wrappedKey = Convert.FromBase64String(stanza.Body[0]);

            // Derive the wrapping key from the passphrase and salt
            var wrappingKey = await Scrypt.DeriveKeyAsync(_passphrase, salt, cancellationToken: cancellationToken);

            // Decrypt the wrapped key
            try
            {
                var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize]; // All zeros
                return dotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(wrappingKey, nonce, wrappedKey);
            }
            catch (CryptographicException)
            {
                // Decryption failed, likely due to an incorrect passphrase
                return null;
            }
        }
    }
}
