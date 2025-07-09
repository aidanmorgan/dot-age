using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core;

/// <summary>
///     Provides high-level API for the age encryption system.
/// </summary>
public class Age
{
    private static readonly ILogger<Age> _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<Age>();

    // The list of identities (for decryption)
    private readonly List<IRecipient> _identities = [];

    // The list of recipients
    private readonly List<IRecipient> _recipients = [];

    /// <summary>
    ///     Adds a recipient to the list of recipients.
    /// </summary>
    /// <param name="recipient">The recipient to add.</param>
    /// <returns>This Age instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when recipient is null.</exception>
    public Age AddRecipient(IRecipient recipient)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        _logger.LogTrace("Adding recipient of type {RecipientType}", recipient.Type);
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
        _logger.LogTrace("Adding identity of type {IdentityType}", identity.Type);
        _identities.Add(identity);
        return this;
    }

    /// <summary>
    ///     Encrypts data for the specified recipients.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <returns>The encrypted data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when plaintext is null.</exception>
    /// <exception cref="AgeEncryptionException">Thrown when no recipients are specified.</exception>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        _logger.LogTrace("Starting encryption with {PlaintextLength} bytes, {RecipientCount} recipients", 
            plaintext.Length, _recipients.Count);

        if (_recipients.Count == 0)
            throw new AgeEncryptionException("No recipients specified");

        // Generate a random 16-byte file key (as per age specification)
        var fileKey = RandomUtils.GenerateRandomBytes(16);

        // Create a stanza for each recipient
        var stanzas = _recipients.Select(recipient => recipient.CreateStanza(fileKey)).ToList();

        // Create the header and calculate its MAC
        var header = new Header(stanzas);
        header.CalculateMac(fileKey);

        // Create the payload
        var payload = new Payload(fileKey);

        // Combine the header and payload
        using var ms = new MemoryStream();
        using var writer = new StreamWriter(ms, Encoding.ASCII);

        // Write the header
        var headerEncoded = header.Encode();
        _logger.LogTrace("Header encoded length: {HeaderLength} bytes", headerEncoded.Length);
        writer.Write(headerEncoded);
        writer.Flush();

        // Write the payload using chunked encryption
        payload.EncryptData(plaintext, ms);

        var result = ms.ToArray();
        return result;
    }

    /// <summary>
    ///     Decrypts data using the specified identities.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ArgumentNullException">Thrown when ciphertext is null.</exception>
    /// <exception cref="AgeDecryptionException">Thrown when no identities are specified or no identity matched any recipient.</exception>
    /// <exception cref="AgeFormatException">Thrown when the age file is malformed.</exception>
    /// <exception cref="AgeCryptoException">Thrown when there's a cryptographic error.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        _logger.LogTrace("Starting decryption with {CiphertextLength} bytes, {IdentityCount} identities", 
            ciphertext.Length, _identities.Count);

        if (_identities.Count == 0)
            throw new AgeDecryptionException("No identities specified");

        // Parse the header and get payload start position
        var parseResult = ParseHeaderWithPosition(ciphertext);
        if (parseResult is not { } headerInfo)
            throw new AgeFormatException("Malformed age file: no header footer found");

        var (header, payloadStart) = headerInfo;
        _logger.LogTrace("Header parsed successfully. Payload starts at position {PayloadStart}, {StanzaCount} stanzas found", 
            payloadStart, header.Stanzas.Count);

        // Create a new stream positioned at the payload start
        using var ms = new MemoryStream(ciphertext);
        ms.Seek(payloadStart, SeekOrigin.Begin);

        // Try to unwrap the file key using each identity
        byte[]? fileKey = null;
        foreach (var identity in _identities)
        {
            foreach (var stanza in header.Stanzas.Where(s => s.Type == identity.Type))
            {
                try
                {
                    fileKey = identity.UnwrapKey(stanza);
                    if (fileKey is not null)
                    {
                        break;
                    }
                }
                catch (CryptographicException ex)
                {
                    _logger.LogTrace("Failed to unwrap key with stanza {StanzaType}: {Error}", stanza.Type, ex.Message);
                    // Continue to next stanza
                }
            }

            if (fileKey is not null)
                break;
        }

        if (fileKey is null)
            throw new AgeDecryptionException("No identity matched any of the recipients");

        // Verify the header MAC
        header.CalculateMac(fileKey);

        if (header.Mac is null)
            throw new AgeCryptoException("Failed to calculate header MAC");

        // The stream is now positioned at the start of the payload
        var payload = new Payload(fileKey);
        var plaintext = payload.DecryptData(ms);

        return plaintext;
    }

    /// <summary>
    ///     Encrypts a file for the specified recipients.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <exception cref="AgeFormatException">Thrown when input or output path is invalid or input file not found.</exception>
    public void EncryptFile(string inputPath, string outputPath)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath))
            throw new AgeFormatException("Input file not found");

        _logger.LogTrace("Encrypting file: {InputPath} -> {OutputPath}", inputPath, outputPath);

        // Read the input file
        var plaintext = File.ReadAllBytes(inputPath);
        _logger.LogTrace("Read {PlaintextLength} bytes from input file", plaintext.Length);

        // Encrypt the plaintext
        var ciphertext = Encrypt(plaintext);

        // Write the output file
        File.WriteAllBytes(outputPath, ciphertext);
        _logger.LogTrace("Wrote {CiphertextLength} bytes to output file", ciphertext.Length);
    }

    /// <summary>
    ///     Encrypts a file for the specified recipients asynchronously.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <exception cref="AgeFormatException">Thrown when input or output path is invalid or input file not found.</exception>
    public async Task EncryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath))
            throw new AgeFormatException("Input file not found");

        _logger.LogTrace("Encrypting file asynchronously: {InputPath} -> {OutputPath}", inputPath, outputPath);

        // Read the input file
        var plaintext = await File.ReadAllBytesAsync(inputPath, cancellationToken);
        _logger.LogTrace("Read {PlaintextLength} bytes from input file", plaintext.Length);

        // Encrypt the plaintext
        var ciphertext = Encrypt(plaintext);

        // Write the output file
        await File.WriteAllBytesAsync(outputPath, ciphertext, cancellationToken);
        _logger.LogTrace("Wrote {CiphertextLength} bytes to output file", ciphertext.Length);
    }

    /// <summary>
    ///     Decrypts a file using the specified identities.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <exception cref="AgeFormatException">Thrown when input or output path is invalid or input file not found.</exception>
    public void DecryptFile(string inputPath, string outputPath)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath))
            throw new AgeFormatException("Input file not found");

        _logger.LogTrace("Decrypting file: {InputPath} -> {OutputPath}", inputPath, outputPath);

        // Read the input file
        var ciphertext = File.ReadAllBytes(inputPath);
        _logger.LogTrace("Read {CiphertextLength} bytes from input file", ciphertext.Length);

        // Decrypt the ciphertext
        var plaintext = Decrypt(ciphertext);

        // Write the output file
        File.WriteAllBytes(outputPath, plaintext);
        _logger.LogTrace("Wrote {PlaintextLength} bytes to output file", plaintext.Length);
    }

    /// <summary>
    ///     Decrypts a file using the specified identities asynchronously.
    /// </summary>
    /// <param name="inputPath">The path to the input file.</param>
    /// <param name="outputPath">The path to the output file.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <exception cref="AgeFormatException">Thrown when input or output path is invalid or input file not found.</exception>
    public async Task DecryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(inputPath))
            throw new AgeFormatException("Input path cannot be null or empty");

        if (string.IsNullOrEmpty(outputPath))
            throw new AgeFormatException("Output path cannot be null or empty");

        if (!File.Exists(inputPath))
            throw new AgeFormatException("Input file not found");

        _logger.LogTrace("Decrypting file asynchronously: {InputPath} -> {OutputPath}", inputPath, outputPath);

        // Read the input file
        var ciphertext = await File.ReadAllBytesAsync(inputPath, cancellationToken);
        _logger.LogTrace("Read {CiphertextLength} bytes from input file", ciphertext.Length);

        // Decrypt the ciphertext
        var plaintext = Decrypt(ciphertext);

        // Write the output file
        await File.WriteAllBytesAsync(outputPath, plaintext, cancellationToken);
        _logger.LogTrace("Wrote {PlaintextLength} bytes to output file", plaintext.Length);
    }

    /// <summary>
    ///     Parses the header from ciphertext and returns the header object and payload start position.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to parse.</param>
    /// <returns>A tuple containing the parsed header and payload start position, or null if parsing fails.</returns>
    private static (Header header, long payloadStart)? ParseHeaderWithPosition(byte[] ciphertext)
    {
        _logger.LogTrace("Parsing header from {CiphertextLength} bytes of ciphertext", ciphertext.Length);

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
                    if (lineBuffer.Count >= 3 && 
                        lineBuffer[0] == (byte)'-' && 
                        lineBuffer[1] == (byte)'-' &&
                        lineBuffer[2] == (byte)'-')
                    {
                        foundFooter = true;
                        headerBytes.AddRange(lineBuffer);
                        _logger.LogTrace("Found footer at position {Position}", ms.Position);
                        break;
                    }

                    headerBytes.AddRange(lineBuffer);
                    lineBuffer.Clear();
                }
            }

            if (!foundFooter)
            {
                _logger.LogTrace("No footer found, malformed age file");
                return null; // Malformed age file
            }

            // Skip any blank lines after the footer
            var payloadStart = ms.Position;
            while (true)
            {
                var skipByte = ms.ReadByte();
                if (skipByte == -1)
                    break;

                if (skipByte != '\n' && skipByte != '\r' && skipByte != ' ' && skipByte != '\t')
                {
                    ms.Seek(-1, SeekOrigin.Current);
                    break;
                }

                payloadStart = ms.Position;
            }

            _logger.LogTrace("Payload starts at position {PayloadStart}", payloadStart);

            var headerText = Encoding.ASCII.GetString(headerBytes.ToArray());
            
            var header = Header.Decode(headerText);
            _logger.LogTrace("Header parsed successfully with {StanzaCount} stanzas", header.Stanzas.Count);
            
            return (header, payloadStart);
        }
        catch (Exception ex)
        {
            _logger.LogTrace("Failed to parse header: {Error}", ex.Message);
            return null; // If we can't parse the header, return null
        }
    }

    /// <summary>
    ///     Parses the header from ciphertext and returns the header object.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to parse.</param>
    /// <returns>The parsed header, or null if parsing fails.</returns>
    private static Header? ParseHeader(byte[] ciphertext) => 
        ParseHeaderWithPosition(ciphertext)?.header;

    /// <summary>
    ///     Detects if the given ciphertext is passphrase-encrypted by checking for scrypt stanzas.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to check.</param>
    /// <returns>True if the file is passphrase-encrypted, false otherwise.</returns>
    public static bool IsPassphraseEncrypted(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        _logger.LogTrace("Checking if ciphertext is passphrase-encrypted");
        var header = ParseHeader(ciphertext);
        var isPassphraseEncrypted = header?.Stanzas.Any(stanza => stanza.Type == "scrypt") ?? false;
        _logger.LogTrace("Is passphrase-encrypted: {IsPassphraseEncrypted}", isPassphraseEncrypted);
        return isPassphraseEncrypted;
    }
}
