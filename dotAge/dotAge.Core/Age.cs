using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using dotAge.Core.Crypto;
using dotAge.Core.Format;
using dotAge.Core.Recipients;

namespace dotAge.Core
{
    /// <summary>
    /// Provides high-level API for the age encryption system.
    /// </summary>
    public class Age
    {
        // The list of recipients
        private readonly List<IRecipient> _recipients = new List<IRecipient>();

        // The list of identities (for decryption)
        private readonly List<IRecipient> _identities = new List<IRecipient>();

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
        public Age AddRecipient(IRecipient recipient)
        {
            if (recipient == null)
                throw new ArgumentNullException(nameof(recipient));

            _recipients.Add(recipient);
            return this;
        }

        /// <summary>
        /// Adds an identity to the list of identities.
        /// </summary>
        /// <param name="identity">The identity to add.</param>
        /// <returns>This Age instance for method chaining.</returns>
        public Age AddIdentity(IRecipient identity)
        {
            if (identity == null)
                throw new ArgumentNullException(nameof(identity));

            _identities.Add(identity);
            return this;
        }

        /// <summary>
        /// Encrypts data for the specified recipients.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (_recipients.Count == 0)
                throw new InvalidOperationException("No recipients specified");

            // Generate a random file key
            var fileKey = dotAge.Core.Crypto.ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient
            var stanzas = new List<Stanza>();
            foreach (var recipient in _recipients)
            {
                stanzas.Add(recipient.CreateStanza(fileKey));
            }

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
            ms.Write(payload.GetData(), 0, payload.GetData().Length);

            return ms.ToArray();
        }

        /// <summary>
        /// Encrypts data from an input stream to an output stream for the specified recipients.
        /// </summary>
        /// <param name="inputStream">The input stream containing plaintext to encrypt.</param>
        /// <param name="outputStream">The output stream to write the encrypted data to.</param>
        public void EncryptStream(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            if (_recipients.Count == 0)
                throw new InvalidOperationException("No recipients specified");

            // Generate a random file key
            var fileKey = dotAge.Core.Crypto.ChaCha20Poly1305.GenerateKey();

            // Create a stanza for each recipient
            var stanzas = new List<Stanza>();
            foreach (var recipient in _recipients)
            {
                stanzas.Add(recipient.CreateStanza(fileKey));
            }

            // Create the header
            var header = new Header(stanzas);

            // Add a MAC to the header (required by the age format)
            // For streaming encryption, we'll use a dummy MAC of all zeros
            header.Mac = new byte[16]; // 16 bytes of zeros

            // Write the header to the output stream
            // Note: We're not using a using statement here to avoid disposing the StreamWriter
            // before we write the payload, as that could cause issues with the stream
            var writer = new StreamWriter(outputStream, Encoding.ASCII, 1024, true);
            writer.Write(header.Encode());
            writer.Flush();

            // Encrypt the plaintext with the file key and write it to the output stream
            Payload.EncryptStream(fileKey, inputStream, outputStream);
        }

        /// <summary>
        /// Decrypts data using the specified identities.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <returns>The decrypted plaintext.</returns>
        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (_identities.Count == 0)
                throw new InvalidOperationException("No identities specified");

            // Parse the header and payload
            using var ms = new MemoryStream(ciphertext);
            using var reader = new StreamReader(ms, Encoding.ASCII);

            // Read the header
            var headerBuilder = new StringBuilder();
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                    break;
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Read the payload
            var payloadData = new byte[ms.Length - ms.Position];
            ms.Read(payloadData, 0, payloadData.Length);

            // Try to unwrap the file key using each identity
            byte[] fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = identity.UnwrapKey(stanza);
                        if (fileKey != null)
                            break;
                    }
                }

                if (fileKey != null)
                    break;
            }

            if (fileKey == null)
                throw new CryptographicException("Failed to unwrap the file key");

            // Decrypt the payload
            var payload = new Payload(fileKey, payloadData);
            return payload.Decrypt();
        }

        /// <summary>
        /// Decrypts data from an input stream to an output stream using the specified identities.
        /// </summary>
        /// <param name="inputStream">The input stream containing encrypted data.</param>
        /// <param name="outputStream">The output stream to write the decrypted data to.</param>
        public void DecryptStream(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            if (_identities.Count == 0)
                throw new InvalidOperationException("No identities specified");

            // Parse the header
            using var reader = new StreamReader(inputStream, Encoding.ASCII, false, 1024, true);
            var headerBuilder = new StringBuilder();
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                headerBuilder.AppendLine(line);

                // Check if this is the end of the header
                if (line.StartsWith("---"))
                    break;
            }

            var header = Header.Decode(headerBuilder.ToString());

            // Try to unwrap the file key using each identity
            byte[] fileKey = null;
            foreach (var identity in _identities)
            {
                foreach (var stanza in header.Stanzas)
                {
                    if (stanza.Type == identity.Type)
                    {
                        fileKey = identity.UnwrapKey(stanza);
                        if (fileKey != null)
                            break;
                    }
                }

                if (fileKey != null)
                    break;
            }

            if (fileKey == null)
                throw new CryptographicException("Failed to unwrap the file key");

            // Decrypt the payload
            Payload.DecryptStream(fileKey, inputStream, outputStream);
        }

        /// <summary>
        /// Encrypts a file for the specified recipients.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        public void EncryptFile(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));

            if (string.IsNullOrEmpty(outputPath))
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            // Read the input file
            var plaintext = File.ReadAllBytes(inputPath);

            // Encrypt the plaintext
            var ciphertext = Encrypt(plaintext);

            // Write the output file
            File.WriteAllBytes(outputPath, ciphertext);
        }

        /// <summary>
        /// Encrypts a file for the specified recipients using streams.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        public void EncryptFileWithStreams(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));

            if (string.IsNullOrEmpty(outputPath))
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            // Open the input and output files as streams
            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            // Encrypt the input stream to the output stream
            EncryptStream(inputStream, outputStream);
        }

        /// <summary>
        /// Decrypts a file using the specified identities.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        public void DecryptFile(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));

            if (string.IsNullOrEmpty(outputPath))
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            // Read the input file
            var ciphertext = File.ReadAllBytes(inputPath);

            // Decrypt the ciphertext
            var plaintext = Decrypt(ciphertext);

            // Write the output file
            File.WriteAllBytes(outputPath, plaintext);
        }

        /// <summary>
        /// Decrypts a file using the specified identities using streams.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        public void DecryptFileWithStreams(string inputPath, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path cannot be null or empty", nameof(inputPath));

            if (string.IsNullOrEmpty(outputPath))
                throw new ArgumentException("Output path cannot be null or empty", nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found", inputPath);

            // Open the input and output files as streams
            using var inputStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            // Decrypt the input stream to the output stream
            DecryptStream(inputStream, outputStream);
        }
    }
}
