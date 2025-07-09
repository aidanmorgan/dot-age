using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;

namespace DotAge.Core;

/// <summary>
///     Provides high-level API for the age encryption system.
/// </summary>
public class Age
{
    // The list of identities (for decryption)
    private readonly List<IRecipient> _identities = new();

    // The list of recipients
    private readonly List<IRecipient> _recipients = new();

    /// <summary>
    ///     Creates a new Age instance.
    /// </summary>
    public Age()
    {
    }

    /// <summary>
    ///     Adds a recipient to the list of recipients.
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
    ///     Adds an identity to the list of identities.
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
    ///     Encrypts data for the specified recipients.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The encrypted data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when plaintext is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no recipients are specified.</exception>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (_recipients.Count == 0) throw new AgeEncryptionException("No recipients specified");

        // Generate a random 16-byte file key (as per age specification)
        var fileKey = RandomUtils.GenerateRandomBytes(16);

        // Create a stanza for each recipient
        var stanzas = _recipients.Select(recipient => recipient.CreateStanza(fileKey)).ToList();

        // Create the header
        var header = new Header(stanzas);

        // Calculate the MAC for the header
        header.CalculateMac(fileKey);

        // Create the payload
        var payload = new Payload(fileKey);

        // Combine the header and payload
        using var ms = new MemoryStream();
        using var writer = new StreamWriter(ms, Encoding.ASCII);

        // Write the header
        writer.Write(header.Encode());
        writer.Flush();

        // Write the payload using chunked encryption
        payload.EncryptData(plaintext, ms);

        return ms.ToArray();
    }


    /// <summary>
    ///     Decrypts data using the specified identities.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ArgumentNullException">Thrown when ciphertext is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no identities are specified.</exception>
    /// <exception cref="CryptographicException">Thrown when the file key cannot be unwrapped.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (_identities.Count == 0) throw new AgeDecryptionException("No identities specified");

        // Parse the header and get payload start position
        var parseResult = ParseHeaderWithPosition(ciphertext);
        if (parseResult == null)
            throw new AgeFormatException("Malformed age file: no header footer found");

        var (header, payloadStart) = parseResult.Value;

        // Create a new stream positioned at the payload start
        using var ms = new MemoryStream(ciphertext);
        ms.Seek(payloadStart, SeekOrigin.Begin);

        // Try to unwrap the file key using each identity
        byte[]? fileKey = null;
        foreach (var identity in _identities)
        {
            foreach (var stanza in header.Stanzas)
                if (stanza.Type == identity.Type)
                    try
                    {
                        fileKey = identity.UnwrapKey(stanza);
                        if (fileKey != null) break;
                    }
                    catch (CryptographicException)
                    {
                        // Continue to next stanza
                    }

            if (fileKey != null) break;
        }

        if (fileKey == null) throw new AgeDecryptionException("No identity matched any of the recipients");

        // Verify the header MAC
        header.CalculateMac(fileKey);
        if (header.Mac == null) throw new AgeCryptoException("Failed to calculate header MAC");

        // The stream is now positioned at the start of the payload (the nonce)
        var payload = new Payload(fileKey);
        return payload.DecryptData(ms);
    }


    /// <summary>
    ///     Encrypts a file for the specified recipients.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
    /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
    public void EncryptFile(string inputPath, string outputPath)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath)) throw new AgeFormatException("Input file not found");

        // Read the input file
        var plaintext = File.ReadAllBytes(inputPath);

        // Encrypt the plaintext
        var ciphertext = Encrypt(plaintext);

        // Write the output file
        File.WriteAllBytes(outputPath, ciphertext);
    }


    /// <summary>
    ///     Decrypts a file using the specified identities.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <exception cref="ArgumentException">Thrown when input or output path is null or empty.</exception>
    /// <exception cref="FileNotFoundException">Thrown when the input file is not found.</exception>
    public void DecryptFile(string inputPath, string outputPath)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath)) throw new AgeFormatException("Input file not found");

        // Read the input file
        var ciphertext = File.ReadAllBytes(inputPath);

        // Decrypt the ciphertext
        var plaintext = Decrypt(ciphertext);

        // Write the output file
        File.WriteAllBytes(outputPath, plaintext);
    }

    /// <summary>
    ///     Parses the header from ciphertext and returns the header object and payload start position.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to parse.</param>
    /// <returns>A tuple containing the parsed header and payload start position, or null if parsing fails.</returns>
    private static (Header header, long payloadStart)? ParseHeaderWithPosition(byte[] ciphertext)
    {
        try
        {
            // Robust header/footer parsing using byte-based line reading
            using var ms = new MemoryStream(ciphertext);
            var headerBytes = new List<byte>();
            var lineBuffer = new List<byte>();
            var foundFooter = false;
            int b;
            while ((b = ms.ReadByte()) != -1)
            {
                lineBuffer.Add((byte)b);
                if (b == '\n')
                {
                    // Check if this line is the footer
                    if (lineBuffer.Count >= 3 && lineBuffer[0] == (byte)'-' && lineBuffer[1] == (byte)'-' &&
                        lineBuffer[2] == (byte)'-')
                    {
                        foundFooter = true;
                        headerBytes.AddRange(lineBuffer);
                        break;
                    }

                    headerBytes.AddRange(lineBuffer);
                    lineBuffer.Clear();
                }
            }

            if (!foundFooter)
                return null; // Malformed age file

            // Skip any blank lines after the footer
            var payloadStart = ms.Position;
            while (true)
            {
                var skipByte = ms.ReadByte();
                if (skipByte == -1) break;
                if (skipByte != '\n' && skipByte != '\r' && skipByte != ' ' && skipByte != '\t')
                {
                    ms.Seek(-1, SeekOrigin.Current);
                    break;
                }

                payloadStart = ms.Position;
            }

            var headerText = Encoding.ASCII.GetString(headerBytes.ToArray());
            var header = Header.Decode(headerText);
            return (header, payloadStart);
        }
        catch
        {
            return null; // If we can't parse the header, return null
        }
    }

    /// <summary>
    ///     Parses the header from ciphertext and returns the header object.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to parse.</param>
    /// <returns>The parsed header, or null if parsing fails.</returns>
    private static Header? ParseHeader(byte[] ciphertext)
    {
        var result = ParseHeaderWithPosition(ciphertext);
        return result?.header;
    }

    /// <summary>
    ///     Detects if the given ciphertext is passphrase-encrypted by checking for scrypt stanzas.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to check.</param>
    /// <returns>True if the file is passphrase-encrypted, false otherwise.</returns>
    public static bool IsPassphraseEncrypted(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        var header = ParseHeader(ciphertext);
        if (header == null)
            return false;

        // Check if any stanza is of type "scrypt"
        return header.Stanzas.Any(stanza => stanza.Type == "scrypt");
    }
}