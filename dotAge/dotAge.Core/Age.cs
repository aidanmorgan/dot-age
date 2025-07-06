using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DotAge.Core.Crypto;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using ChaCha20Poly1305 = DotAge.Core.Crypto.ChaCha20Poly1305;

namespace DotAge.Core
{
    /// <summary>
    /// Provides high-level API for the age encryption system.
    /// </summary>
    public class Age
    {
        // The list of recipients
        private readonly List<IRecipient> _recipients = new();

        // The list of identities (for decryption)
        private readonly List<IRecipient> _identities = new();

        /// <summary>
        /// Creates a new Age instance.
        /// </summary>
        public Age()
        {
        }

        /// <summary>
        /// Adds a recipient to the list of recipients.
        /// </summary>
        /// <param name="recipient">The recipient to add.</param>
        /// <returns>This Age instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when recipient is null.</exception>
        public Age AddRecipient(IRecipient recipient)
        {
            ArgumentNullException.ThrowIfNull(recipient);

            _recipients.Add(recipient);
            return this;
        }

        /// <summary>
        /// Adds an identity to the list of identities.
        /// </summary>
        /// <param name="identity">The identity to add.</param>
        /// <returns>This Age instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when identity is null.</exception>
        public Age AddIdentity(IRecipient identity)
        {
            ArgumentNullException.ThrowIfNull(identity);

            _identities.Add(identity);
            return this;
        }

        /// <summary>
        /// Encrypts data for the specified recipients.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plaintext is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no recipients are specified.</exception>
        public byte[] Encrypt(byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(plaintext);

            if (_recipients.Count == 0)
            {
                throw new InvalidOperationException("No recipients specified");
            }

            // Generate a random file key
            var fileKey = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient
            var stanzas = _recipients.Select(recipient => recipient.CreateStanza(fileKey)).ToList();

            // Create the header
            var header = new Header(stanzas);

            // Encrypt the plaintext with the file key
            var payload = Payload.Encrypt(fileKey, plaintext);

            // Combine the header and payload
            using var ms = new MemoryStream();
            using var writer = new StreamWriter(ms, Encoding.ASCII);

            // Write the header
            writer.Write(header.Encode());
            writer.Flush();

            // Write the payload
            var payloadData = payload.GetData();
            ms.Write(payloadData, 0, payloadData.Length);

            return ms.ToArray();
        }

        /// <summary>
        /// Encrypts data for the specified recipients asynchronously.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when plaintext is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no recipients are specified.</exception>
        public async Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(plaintext);

            if (_recipients.Count == 0)
            {
                throw new InvalidOperationException("No recipients specified");
            }

            // Generate a random file key
            var fileKey = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient asynchronously
            var stanzaTasks = _recipients.Select(recipient => recipient.CreateStanzaAsync(fileKey, cancellationToken));
            var stanzas = await Task.WhenAll(stanzaTasks).ConfigureAwait(false);

            // Create the header
            var header = new Header(stanzas.ToList());

            // Encrypt the plaintext with the file key
            var payload = Payload.Encrypt(fileKey, plaintext);

            // Combine the header and payload
            using var ms = new MemoryStream();
            using var writer = new StreamWriter(ms, Encoding.ASCII);

            // Write the header
            await writer.WriteAsync(header.Encode()).ConfigureAwait(false);
            await writer.FlushAsync().ConfigureAwait(false);

            // Write the payload
            var payloadData = payload.GetData();
            await ms.WriteAsync(payloadData, 0, payloadData.Length, cancellationToken).ConfigureAwait(false);

            return ms.ToArray();
        }


        /// <summary>
        /// Decrypts data using the specified identities.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <returns>The decrypted plaintext.</returns>
        /// <exception cref="ArgumentNullException">Thrown when ciphertext is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no identities are specified.</exception>
        /// <exception cref="CryptographicException">Thrown when the file key cannot be unwrapped.</exception>
        public byte[] Decrypt(byte[] ciphertext)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);

            if (_identities.Count == 0)
            {
                throw new InvalidOperationException("No identities specified");
            }

            // Parse the header and payload
            using var ms = new MemoryStream(ciphertext);
            using var reader = new StreamReader(ms, Encoding.ASCII);

            // Read the header
            var headerBuilder = new StringBuilder();
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                {
                    break;
                }
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Read the payload
            var payloadData = new byte[ms.Length - ms.Position];
            var bytesRead = ms.Read(payloadData, 0, payloadData.Length);

            // Ensure we read the correct number of bytes
            if (bytesRead < payloadData.Length)
            {
                // Resize the array to the actual number of bytes read
                Array.Resize(ref payloadData, bytesRead);
            }

            // Try to unwrap the file key using each identity
            byte[]? fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = identity.UnwrapKey(stanza);
                        if (fileKey != null)
                        {
                            break;
                        }
                    }
                }

                if (fileKey != null)
                {
                    break;
                }
            }

            if (fileKey == null)
            {
                throw new CryptographicException("Failed to unwrap the file key");
            }

            // Decrypt the payload
            var payload = new Payload(fileKey, payloadData);
            return payload.Decrypt();
        }

        /// <summary>
        /// Decrypts data using the specified identities asynchronously.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the decrypted plaintext.</returns>
        /// <exception cref="ArgumentNullException">Thrown when ciphertext is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no identities are specified.</exception>
        /// <exception cref="CryptographicException">Thrown when the file key cannot be unwrapped.</exception>
        public async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);

            if (_identities.Count == 0)
            {
                throw new InvalidOperationException("No identities specified");
            }

            // Parse the header and payload
            using var ms = new MemoryStream(ciphertext);
            using var reader = new StreamReader(ms, Encoding.ASCII);

            // Read the header
            var headerBuilder = new StringBuilder();
            string? line;
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                {
                    break;
                }
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Read the payload
            var payloadData = new byte[ms.Length - ms.Position];
            var bytesRead = await ms.ReadAsync(payloadData, 0, payloadData.Length, cancellationToken).ConfigureAwait(false);

            // Ensure we read the correct number of bytes
            if (bytesRead < payloadData.Length)
            {
                // Resize the array to the actual number of bytes read
                Array.Resize(ref payloadData, bytesRead);
            }

            // Try to unwrap the file key using each identity asynchronously
            byte[]? fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = await identity.UnwrapKeyAsync(stanza, cancellationToken).ConfigureAwait(false);
                        if (fileKey != null)
                        {
                            break;
                        }
                    }
                }

                if (fileKey != null)
                {
                    break;
                }
            }

            if (fileKey == null)
            {
                throw new CryptographicException("Failed to unwrap the file key");
            }

            // Decrypt the payload
            var payload = new Payload(fileKey, payloadData);
            return payload.Decrypt();
        }


        /// <summary>
        /// Encrypts a file for the specified recipients.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public void EncryptFile(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            // Read the input file
            var plaintext = File.ReadAllBytes(inputPath);

            // Encrypt the plaintext
            var ciphertext = Encrypt(plaintext);

            // Write the output file
            File.WriteAllBytes(outputPath, ciphertext);
        }

        /// <summary>
        /// Encrypts a file for the specified recipients asynchronously.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public async Task EncryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            // Read the input file
            var plaintext = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);

            // Encrypt the plaintext
            var ciphertext = await EncryptAsync(plaintext, cancellationToken).ConfigureAwait(false);

            // Write the output file
            await File.WriteAllBytesAsync(outputPath, ciphertext, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypts a file using the specified identities.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public void DecryptFile(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            // Read the input file
            var ciphertext = File.ReadAllBytes(inputPath);

            // Decrypt the ciphertext
            var plaintext = Decrypt(ciphertext);

            // Write the output file
            File.WriteAllBytes(outputPath, plaintext);
        }

        /// <summary>
        /// Decrypts a file using the specified identities asynchronously.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public async Task DecryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            // Read the input file
            var ciphertext = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);

            // Decrypt the ciphertext
            var plaintext = await DecryptAsync(ciphertext, cancellationToken).ConfigureAwait(false);

            // Write the output file
            await File.WriteAllBytesAsync(outputPath, plaintext, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypts data using a stream-based approach.
        /// </summary>
        /// <param name="inputStream">The input stream containing the plaintext.</param>
        /// <param name="outputStream">The output stream to write the ciphertext to.</param>
        /// <exception cref="ArgumentNullException">Thrown when inputStream or outputStream is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no recipients are specified.</exception>
        public void EncryptStream(Stream inputStream, Stream outputStream)
        {
            ArgumentNullException.ThrowIfNull(inputStream);
            ArgumentNullException.ThrowIfNull(outputStream);

            if (_recipients.Count == 0)
            {
                throw new InvalidOperationException("No recipients specified");
            }

            // Generate a random file key
            var fileKey = DotAge.Core.Crypto.ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient
            var stanzas = _recipients.Select(recipient => recipient.CreateStanza(fileKey)).ToList();

            // Create the header
            var header = new Header(stanzas);

            // Write the header to the output stream
            using var writer = new StreamWriter(outputStream, Encoding.ASCII, leaveOpen: true);
            writer.Write(header.Encode());
            writer.Flush();

            // Create a payload and encrypt the input stream
            Payload.EncryptStream(fileKey, inputStream, outputStream);
        }

        /// <summary>
        /// Encrypts data using a stream-based approach asynchronously.
        /// </summary>
        /// <param name="inputStream">The input stream containing the plaintext.</param>
        /// <param name="outputStream">The output stream to write the ciphertext to.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when inputStream or outputStream is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no recipients are specified.</exception>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(inputStream);
            ArgumentNullException.ThrowIfNull(outputStream);

            if (_recipients.Count == 0)
            {
                throw new InvalidOperationException("No recipients specified");
            }

            // Generate a random file key
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient asynchronously
            var stanzaTasks = _recipients.Select(recipient => recipient.CreateStanzaAsync(fileKey, cancellationToken));
            var stanzas = await Task.WhenAll(stanzaTasks).ConfigureAwait(false);

            // Create the header
            var header = new Header(stanzas.ToList());

            // Write the header to the output stream
            using var writer = new StreamWriter(outputStream, Encoding.ASCII, leaveOpen: true);
            await writer.WriteAsync(header.Encode()).ConfigureAwait(false);
            await writer.FlushAsync().ConfigureAwait(false);

            // Create a payload and encrypt the input stream
            await Payload.EncryptStreamAsync(fileKey, inputStream, outputStream, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypts data using a stream-based approach.
        /// </summary>
        /// <param name="inputStream">The input stream containing the ciphertext.</param>
        /// <param name="outputStream">The output stream to write the plaintext to.</param>
        /// <exception cref="ArgumentNullException">Thrown when inputStream or outputStream is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no identities are specified.</exception>
        /// <exception cref="CryptographicException">Thrown when the file key cannot be unwrapped.</exception>
        public void DecryptStream(Stream inputStream, Stream outputStream)
        {
            ArgumentNullException.ThrowIfNull(inputStream);
            ArgumentNullException.ThrowIfNull(outputStream);

            if (_identities.Count == 0)
            {
                throw new InvalidOperationException("No identities specified");
            }

            // Read the header
            using var reader = new StreamReader(inputStream, Encoding.ASCII, leaveOpen: true);
            var headerBuilder = new StringBuilder();
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                {
                    break;
                }
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Try to unwrap the file key using each identity
            byte[]? fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = identity.UnwrapKey(stanza);
                        if (fileKey != null)
                        {
                            break;
                        }
                    }
                }

                if (fileKey != null)
                {
                    break;
                }
            }

            if (fileKey == null)
            {
                throw new CryptographicException("Failed to unwrap the file key");
            }

            // Decrypt the payload
            Payload.DecryptStream(fileKey, inputStream, outputStream);
        }

        /// <summary>
        /// Decrypts data using a stream-based approach asynchronously.
        /// </summary>
        /// <param name="inputStream">The input stream containing the ciphertext.</param>
        /// <param name="outputStream">The output stream to write the plaintext to.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when inputStream or outputStream is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when no identities are specified.</exception>
        /// <exception cref="CryptographicException">Thrown when the file key cannot be unwrapped.</exception>
        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(inputStream);
            ArgumentNullException.ThrowIfNull(outputStream);

            if (_identities.Count == 0)
            {
                throw new InvalidOperationException("No identities specified");
            }

            // Read the header
            using var reader = new StreamReader(inputStream, Encoding.ASCII, leaveOpen: true);
            var headerBuilder = new StringBuilder();
            string? line;
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                {
                    break;
                }
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Try to unwrap the file key using each identity asynchronously
            byte[]? fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = await identity.UnwrapKeyAsync(stanza, cancellationToken).ConfigureAwait(false);
                        if (fileKey != null)
                        {
                            break;
                        }
                    }
                }

                if (fileKey != null)
                {
                    break;
                }
            }

            if (fileKey == null)
            {
                throw new CryptographicException("Failed to unwrap the file key");
            }

            // Decrypt the payload
            await Payload.DecryptStreamAsync(fileKey, inputStream, outputStream, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypts a file using a stream-based approach.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public void EncryptFileWithStreams(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            EncryptStream(inputStream, outputStream);
        }

        /// <summary>
        /// Encrypts a file using a stream-based approach asynchronously.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public async Task EncryptFileWithStreamsAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            await EncryptStreamAsync(inputStream, outputStream, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypts a file using a stream-based approach.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public void DecryptFileWithStreams(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            DecryptStream(inputStream, outputStream);
        }

        /// <summary>
        /// Decrypts a file using a stream-based approach asynchronously.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
        public async Task DecryptFileWithStreamsAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));
            }

            if (!File.Exists(inputPath))
            {
                throw new FileNotFoundException("Input file not found", inputPath);
            }

            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            await DecryptStreamAsync(inputStream, outputStream, cancellationToken).ConfigureAwait(false);
        }
    }
}
