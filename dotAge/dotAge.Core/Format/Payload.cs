using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Crypto;

namespace DotAge.Core.Format
{
    /// <summary>
    /// Represents the payload of an age-encrypted file.
    /// </summary>
    public class Payload
    {
        // The ChaCha20-Poly1305 key used to encrypt the payload
        private readonly byte[] _key;

        // The encrypted data
        private readonly byte[] _data;

        /// <summary>
        /// Creates a new payload with the specified key and data.
        /// </summary>
        /// <param name="key">The ChaCha20-Poly1305 key.</param>
        /// <param name="data">The encrypted data.</param>
        public Payload(byte[] key, byte[] data)
        {
            if (key == null || key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

            _key = key;
            _data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Encrypts data using the payload key.
        /// </summary>
        /// <param name="key">The ChaCha20-Poly1305 key.</param>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <returns>A new payload containing the encrypted data.</returns>
        public static Payload Encrypt(byte[] key, byte[] plaintext)
        {
            if (key == null || key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            // Generate a random nonce
            var nonce = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateNonce();

            // Encrypt the plaintext
            var ciphertext = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Combine the nonce and ciphertext
            var data = new byte[nonce.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, data, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, data, nonce.Length, ciphertext.Length);

            return new Payload(key, data);
        }


        /// <summary>
        /// Decrypts the payload.
        /// </summary>
        /// <returns>The decrypted plaintext.</returns>
        public byte[] Decrypt()
        {
            // Check if the payload data is long enough to contain a nonce and at least some ciphertext
            if (_data.Length < DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize + DotAge.Core.Crypto.ChaCha20Poly1305.TagSize)
                throw new InvalidOperationException("Payload data is too short");

            // Extract the nonce and ciphertext
            var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
            var ciphertext = new byte[_data.Length - DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
            Buffer.BlockCopy(_data, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(_data, nonce.Length, ciphertext, 0, ciphertext.Length);

            // Decrypt the ciphertext
            return DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(_key, nonce, ciphertext);
        }


        /// <summary>
        /// Gets the encrypted data.
        /// </summary>
        /// <returns>The encrypted data.</returns>
        public byte[] GetData()
        {
            return _data;
        }

        /// <summary>
        /// Gets the key used to encrypt the payload.
        /// </summary>
        /// <returns>The key.</returns>
        public byte[] GetKey()
        {
            return _key;
        }

        /// <summary>
        /// Encrypts a stream using the specified key.
        /// </summary>
        /// <param name="key">The ChaCha20-Poly1305 key.</param>
        /// <param name="inputStream">The input stream containing the plaintext.</param>
        /// <param name="outputStream">The output stream to write the ciphertext to.</param>
        public static void EncryptStream(byte[] key, Stream inputStream, Stream outputStream)
        {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(inputStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        if (key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
            throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

        // Generate a random nonce
        var nonce = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateNonce();

        // Write the nonce to the output stream
        outputStream.Write(nonce, 0, nonce.Length);

        // Create a buffer for reading from the input stream
        var buffer = new byte[4096];
        int bytesRead;

        // Read from the input stream and encrypt to the output stream
        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            var plaintext = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, plaintext, 0, bytesRead);

            var ciphertext = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, plaintext);
            outputStream.Write(ciphertext, 0, ciphertext.Length);
        }
    }

    /// <summary>
    /// Encrypts a stream using the specified key asynchronously.
    /// </summary>
    /// <param name="key">The ChaCha20-Poly1305 key.</param>
    /// <param name="inputStream">The input stream containing the plaintext.</param>
    /// <param name="outputStream">The output stream to write the ciphertext to.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task EncryptStreamAsync(byte[] key, Stream inputStream, Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(inputStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        if (key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
            throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

        // Generate a random nonce
        var nonce = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateNonce();

        // Write the nonce to the output stream
        await outputStream.WriteAsync(nonce, 0, nonce.Length, cancellationToken).ConfigureAwait(false);

        // Create a buffer for reading from the input stream
        var buffer = new byte[4096];
        int bytesRead;

        // Read from the input stream and encrypt to the output stream
        while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
        {
            var plaintext = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, plaintext, 0, bytesRead);

            var ciphertext = DotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, plaintext);
            await outputStream.WriteAsync(ciphertext, 0, ciphertext.Length, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Decrypts a stream using the specified key.
    /// </summary>
    /// <param name="key">The ChaCha20-Poly1305 key.</param>
    /// <param name="inputStream">The input stream containing the ciphertext.</param>
    /// <param name="outputStream">The output stream to write the plaintext to.</param>
    public static void DecryptStream(byte[] key, Stream inputStream, Stream outputStream)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(inputStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        if (key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
            throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

        // Read the nonce from the input stream
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
        int bytesRead = inputStream.Read(nonce, 0, nonce.Length);
        if (bytesRead != nonce.Length)
            throw new InvalidOperationException("Failed to read nonce from input stream");

        // Create a buffer for reading from the input stream
        var buffer = new byte[4096 + DotAge.Core.Crypto.ChaCha20Poly1305.TagSize]; // Add space for the authentication tag

        // Read from the input stream and decrypt to the output stream
        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            var ciphertext = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, ciphertext, 0, bytesRead);

            var plaintext = DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);
            outputStream.Write(plaintext, 0, plaintext.Length);
        }
    }

    /// <summary>
    /// Decrypts a stream using the specified key asynchronously.
    /// </summary>
    /// <param name="key">The ChaCha20-Poly1305 key.</param>
    /// <param name="inputStream">The input stream containing the ciphertext.</param>
    /// <param name="outputStream">The output stream to write the plaintext to.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task DecryptStreamAsync(byte[] key, Stream inputStream, Stream outputStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(inputStream);
        ArgumentNullException.ThrowIfNull(outputStream);

        if (key.Length != DotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
            throw new ArgumentException($"Key must be {DotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

        // Read the nonce from the input stream
        var nonce = new byte[DotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
        int bytesRead = await inputStream.ReadAsync(nonce, 0, nonce.Length, cancellationToken).ConfigureAwait(false);
        if (bytesRead != nonce.Length)
            throw new InvalidOperationException("Failed to read nonce from input stream");

        // Create a buffer for reading from the input stream
        var buffer = new byte[4096 + DotAge.Core.Crypto.ChaCha20Poly1305.TagSize]; // Add space for the authentication tag

        // Read from the input stream and decrypt to the output stream
        while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
        {
            var ciphertext = new byte[bytesRead];
            Buffer.BlockCopy(buffer, 0, ciphertext, 0, bytesRead);

            var plaintext = DotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);
            await outputStream.WriteAsync(plaintext, 0, plaintext.Length, cancellationToken).ConfigureAwait(false);
        }
    }
}
}
