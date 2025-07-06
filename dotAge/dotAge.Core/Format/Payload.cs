using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using dotAge.Core.Crypto;

namespace dotAge.Core.Format
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
            if (key == null || key.Length != dotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {dotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

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
            if (key == null || key.Length != dotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {dotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            // Generate a random nonce
            var nonce = dotAge.Core.Crypto.ChaCha20Poly1305.GenerateNonce();

            // Encrypt the plaintext
            var ciphertext = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Combine the nonce and ciphertext
            var data = new byte[nonce.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, data, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, data, nonce.Length, ciphertext.Length);

            return new Payload(key, data);
        }

        /// <summary>
        /// Encrypts data from an input stream to an output stream using the payload key.
        /// </summary>
        /// <param name="key">The ChaCha20-Poly1305 key.</param>
        /// <param name="inputStream">The input stream containing plaintext to encrypt.</param>
        /// <param name="outputStream">The output stream to write the encrypted data to.</param>
        public static void EncryptStream(byte[] key, Stream inputStream, Stream outputStream)
        {
            if (key == null || key.Length != dotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {dotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            // Generate a random nonce base
            var nonceBase = dotAge.Core.Crypto.ChaCha20Poly1305.GenerateNonce();

            // Write the nonce base to the output stream
            outputStream.Write(nonceBase, 0, nonceBase.Length);

            // Read the plaintext from the input stream and encrypt it in chunks
            const int bufferSize = 4096;
            var buffer = new byte[bufferSize];
            int bytesRead;
            long counter = 0;

            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                // Create a unique nonce for this chunk by XORing the counter with the nonce base
                var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
                Buffer.BlockCopy(nonceBase, 0, nonce, 0, nonce.Length);

                // XOR the last 8 bytes of the nonce with the counter
                for (int i = 0; i < 8 && i < nonce.Length; i++)
                {
                    nonce[nonce.Length - 1 - i] ^= (byte)((counter >> (i * 8)) & 0xFF);
                }

                // Increment the counter for the next chunk
                counter++;

                // If we read a full buffer, encrypt and write it
                if (bytesRead == bufferSize)
                {
                    var ciphertext = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, buffer);
                    outputStream.Write(ciphertext, 0, ciphertext.Length);
                }
                else
                {
                    // If we read a partial buffer, create a new array with just the data we read
                    var partialBuffer = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, partialBuffer, 0, bytesRead);
                    var ciphertext = dotAge.Core.Crypto.ChaCha20Poly1305.Encrypt(key, nonce, partialBuffer);
                    outputStream.Write(ciphertext, 0, ciphertext.Length);
                }
            }
        }

        /// <summary>
        /// Decrypts the payload.
        /// </summary>
        /// <returns>The decrypted plaintext.</returns>
        public byte[] Decrypt()
        {
            // Check if the payload data is long enough to contain a nonce and at least some ciphertext
            if (_data.Length < dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize + dotAge.Core.Crypto.ChaCha20Poly1305.TagSize)
                throw new InvalidOperationException("Payload data is too short");

            // Extract the nonce and ciphertext
            var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
            var ciphertext = new byte[_data.Length - dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
            Buffer.BlockCopy(_data, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(_data, nonce.Length, ciphertext, 0, ciphertext.Length);

            // Decrypt the ciphertext
            return dotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(_key, nonce, ciphertext);
        }

        /// <summary>
        /// Decrypts data from an input stream to an output stream.
        /// </summary>
        /// <param name="key">The ChaCha20-Poly1305 key.</param>
        /// <param name="inputStream">The input stream containing encrypted data.</param>
        /// <param name="outputStream">The output stream to write the decrypted data to.</param>
        public static void DecryptStream(byte[] key, Stream inputStream, Stream outputStream)
        {
            if (key == null || key.Length != dotAge.Core.Crypto.ChaCha20Poly1305.KeySize)
                throw new ArgumentException($"Key must be {dotAge.Core.Crypto.ChaCha20Poly1305.KeySize} bytes", nameof(key));

            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            // Read the nonce base from the input stream
            var nonceBase = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
            int bytesRead = inputStream.Read(nonceBase, 0, nonceBase.Length);
            if (bytesRead != nonceBase.Length)
                throw new InvalidOperationException("Failed to read nonce from input stream");

            // Read the ciphertext from the input stream and decrypt it in chunks
            const int bufferSize = 4096 + dotAge.Core.Crypto.ChaCha20Poly1305.TagSize; // Buffer size plus tag size
            var buffer = new byte[bufferSize];
            long counter = 0;

            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                // Create a unique nonce for this chunk by XORing the counter with the nonce base
                var nonce = new byte[dotAge.Core.Crypto.ChaCha20Poly1305.NonceSize];
                Buffer.BlockCopy(nonceBase, 0, nonce, 0, nonce.Length);

                // XOR the last 8 bytes of the nonce with the counter
                for (int i = 0; i < 8 && i < nonce.Length; i++)
                {
                    nonce[nonce.Length - 1 - i] ^= (byte)((counter >> (i * 8)) & 0xFF);
                }

                // Increment the counter for the next chunk
                counter++;

                // If we read data, decrypt it
                if (bytesRead > dotAge.Core.Crypto.ChaCha20Poly1305.TagSize)
                {
                    var ciphertextChunk = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, ciphertextChunk, 0, bytesRead);
                    var plaintextChunk = dotAge.Core.Crypto.ChaCha20Poly1305.Decrypt(key, nonce, ciphertextChunk);
                    outputStream.Write(plaintextChunk, 0, plaintextChunk.Length);
                }
                else
                {
                    throw new InvalidOperationException("Ciphertext chunk is too small");
                }
            }
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
    }
}
