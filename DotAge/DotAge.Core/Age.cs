using System.Collections.ObjectModel;
using System.Text;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core;

/// <summary>
///     Main age encryption/decryption functionality.
///     Implements the age file format specification.
/// </summary>
public class Age
{
    private static readonly Lazy<ILogger> _logger = new(() => LoggerFactory.CreateLogger(nameof(Age)));
    private readonly List<IRecipient> _identities = new();
    private readonly List<IRecipient> _recipients = new();

    /// <summary>
    ///     Gets a read-only view of the configured recipients.
    /// </summary>
    public IReadOnlyList<IRecipient> Recipients => _recipients.AsReadOnly();

    /// <summary>
    ///     Gets a read-only view of the configured identities.
    /// </summary>
    public IReadOnlyList<IRecipient> Identities => _identities.AsReadOnly();

    /// <summary>
    ///     Adds a recipient for encryption.
    /// </summary>
    /// <param name="recipient">The recipient to add.</param>
    public void AddRecipient(IRecipient recipient)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        _recipients.Add(recipient);
    }

    /// <summary>
    ///     Adds an identity for decryption.
    /// </summary>
    /// <param name="identity">The identity to add.</param>
    public void AddIdentity(IRecipient identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _identities.Add(identity);
    }

    /// <summary>
    ///     Encrypts data using the configured recipients.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The encrypted data.</returns>
    public byte[] Encrypt(byte[] plaintext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        cancellationToken.ThrowIfCancellationRequested();
        
        if (_recipients.Count == 0)
            throw new AgeEncryptionException("No recipients configured for encryption");

        _logger.Value.LogTrace("=== AGE ENCRYPT START ===");
        _logger.Value.LogTrace("Plaintext length: {PlaintextLength} bytes", plaintext.Length);
        _logger.Value.LogTrace("Plaintext (first 64 bytes): {PlaintextPrefix}",
            BitConverter.ToString(plaintext.Take(64).ToArray()));

        // Generate a random file key (16 bytes as per age spec)
        using var secureFileKey = SecureMemoryUtils.CreateSecureByteArray(RandomUtils.GenerateRandomBytes(16));
        var fileKey = secureFileKey.Data;
        _logger.Value.LogTrace("Generated file key: {FileKey}", BitConverter.ToString(fileKey));
        
        cancellationToken.ThrowIfCancellationRequested();

        // Create header with recipients
        var header = new Header();
        foreach (var recipient in _recipients)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stanza = recipient.CreateStanza(fileKey);
            header.Stanzas.Add(stanza);
        }

        // Calculate header MAC
        cancellationToken.ThrowIfCancellationRequested();
        header.CalculateMac(fileKey);

        // Create payload and encrypt data
        cancellationToken.ThrowIfCancellationRequested();
        var payload = new Payload(fileKey);
        using var ms = new MemoryStream();
        payload.EncryptData(plaintext, ms);
        var encryptedPayload = ms.ToArray();

        _logger.Value.LogTrace("Encrypted payload length: {PayloadLength} bytes", encryptedPayload.Length);
        _logger.Value.LogTrace("Encrypted payload (first 64 bytes): {PayloadPrefix}",
            BitConverter.ToString(encryptedPayload.Take(64).ToArray()));

        // Combine header and payload
        cancellationToken.ThrowIfCancellationRequested();
        var headerEncoded = header.Encode();
        var headerBytes = Encoding.ASCII.GetBytes(headerEncoded);
        var result = new byte[headerBytes.Length + encryptedPayload.Length];
        Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
        Buffer.BlockCopy(encryptedPayload, 0, result, headerBytes.Length, encryptedPayload.Length);
        
        // Clear sensitive header data
        SecureMemoryUtils.ClearSensitiveData(headerBytes);

        _logger.Value.LogTrace("Final ciphertext length: {CiphertextLength} bytes", result.Length);
        _logger.Value.LogTrace("=== AGE ENCRYPT END ===");
        return result;
    }

    /// <summary>
    ///     Decrypts data using the configured identities.
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The decrypted data.</returns>
    public byte[] Decrypt(byte[] ciphertext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        cancellationToken.ThrowIfCancellationRequested();
        
        if (_identities.Count == 0)
            throw new AgeDecryptionException("No identities configured for decryption");

        _logger.Value.LogTrace("=== AGE DECRYPT START ===");
        _logger.Value.LogTrace("Ciphertext length: {CiphertextLength} bytes", ciphertext.Length);
        _logger.Value.LogTrace("Ciphertext (first 64 bytes): {CiphertextPrefix}",
            BitConverter.ToString(ciphertext.Take(64).ToArray()));

        // Parse header and get payload start position
        cancellationToken.ThrowIfCancellationRequested();
        var (header, payloadStart) = ParseHeader(ciphertext);
        _logger.Value.LogTrace("Parsed header with {StanzaCount} stanzas", header.Stanzas.Count);
        _logger.Value.LogTrace("Payload starts at position: {PayloadStart}", payloadStart);

        // Try to unwrap the file key using any identity
        byte[]? fileKey = null;
        foreach (var identity in _identities)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.Value.LogTrace("Trying identity: {IdentityType}", identity.GetType().Name);
            foreach (var stanza in header.Stanzas)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _logger.Value.LogTrace("Processing stanza type: '{StanzaType}' with identity: {IdentityType}",
                    stanza.Type, identity.GetType().Name);

                // Only try to unwrap stanzas that this identity supports
                if (!identity.SupportsStanzaType(stanza.Type))
                {
                    _logger.Value.LogTrace(
                        "Skipping stanza type '{StanzaType}' - not supported by identity type '{IdentityType}'",
                        stanza.Type, identity.Type);
                    continue;
                }

                _logger.Value.LogTrace(
                    "Attempting to unwrap stanza type '{StanzaType}' with identity type '{IdentityType}'", stanza.Type,
                    identity.Type);
                try
                {
                    var candidate = identity.UnwrapKey(stanza);
                    if (candidate != null)
                    {
                        fileKey = candidate;
                        break;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Value.LogTrace(ex,
                        "Failed to unwrap file key with identity {IdentityType} and stanza type {StanzaType}",
                        identity.GetType().Name, stanza.Type);
                }
            }

            if (fileKey != null)
                break;
        }

        if (fileKey == null)
        {
            _logger.Value.LogTrace("Failed to unwrap file key with any identity");
            throw new AgeDecryptionException("Failed to unwrap file key with any identity");
        }

        // Use secure wrapper for file key
        using var secureFileKey = SecureMemoryUtils.CreateSecureByteArray(fileKey);
        
        // Verify header MAC
        cancellationToken.ThrowIfCancellationRequested();
        header.CalculateMac(secureFileKey.Data);

        // Decrypt the payload using the correct payload start position
        cancellationToken.ThrowIfCancellationRequested();
        var encryptedPayload = new byte[ciphertext.Length - payloadStart];
        Buffer.BlockCopy(ciphertext, (int)payloadStart, encryptedPayload, 0, encryptedPayload.Length);

        _logger.Value.LogTrace("Encrypted payload length: {PayloadLength} bytes", encryptedPayload.Length);
        _logger.Value.LogTrace("Encrypted payload (first 64 bytes): {PayloadPrefix}",
            BitConverter.ToString(encryptedPayload.Take(64).ToArray()));

        var payload = new Payload(secureFileKey.Data);
        using var ms = new MemoryStream(encryptedPayload);
        var decryptedData = payload.DecryptData(ms);
        
        // Clear sensitive payload data
        SecureMemoryUtils.ClearSensitiveData(encryptedPayload);

        _logger.Value.LogTrace("Decrypted data length: {DecryptedLength} bytes", decryptedData.Length);
        _logger.Value.LogTrace("Decrypted data (first 64 bytes): {DecryptedPrefix}",
            BitConverter.ToString(decryptedData.Take(64).ToArray()));
        _logger.Value.LogTrace("=== AGE DECRYPT END ===");
        return decryptedData;
    }

    /// <summary>
    ///     Encrypts a file.
    /// </summary>
    /// <param name="inputPath">The input file path.</param>
    /// <param name="outputPath">The output file path.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public void EncryptFile(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        ValidationUtils.ValidateStringNotNullOrEmpty(inputPath);
        ValidationUtils.ValidateStringNotNullOrEmpty(outputPath);
        cancellationToken.ThrowIfCancellationRequested();

        var plaintext = File.ReadAllBytes(inputPath);
        try
        {
            var ciphertext = Encrypt(plaintext, cancellationToken);
            File.WriteAllBytes(outputPath, ciphertext);
        }
        finally
        {
            // Clear sensitive plaintext data
            SecureMemoryUtils.ClearSensitiveData(plaintext);
        }
    }

    /// <summary>
    ///     Encrypts a file asynchronously.
    /// </summary>
    /// <param name="inputPath">The input file path.</param>
    /// <param name="outputPath">The output file path.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task EncryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        ValidationUtils.ValidateStringNotNullOrEmpty(inputPath);
        ValidationUtils.ValidateStringNotNullOrEmpty(outputPath);
        cancellationToken.ThrowIfCancellationRequested();

        var plaintext = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);
        try
        {
            var ciphertext = await Task.Run(() => Encrypt(plaintext, cancellationToken), cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(outputPath, ciphertext, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear sensitive plaintext data
            SecureMemoryUtils.ClearSensitiveData(plaintext);
        }
    }

    /// <summary>
    ///     Decrypts a file.
    /// </summary>
    /// <param name="inputPath">The input file path.</param>
    /// <param name="outputPath">The output file path.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public void DecryptFile(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        ValidationUtils.ValidateStringNotNullOrEmpty(inputPath);
        ValidationUtils.ValidateStringNotNullOrEmpty(outputPath);
        cancellationToken.ThrowIfCancellationRequested();

        var ciphertext = File.ReadAllBytes(inputPath);
        var plaintext = Decrypt(ciphertext, cancellationToken);
        File.WriteAllBytes(outputPath, plaintext);
    }

    /// <summary>
    ///     Decrypts a file asynchronously.
    /// </summary>
    /// <param name="inputPath">The input file path.</param>
    /// <param name="outputPath">The output file path.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task DecryptFileAsync(string inputPath, string outputPath, CancellationToken cancellationToken = default)
    {
        ValidationUtils.ValidateStringNotNullOrEmpty(inputPath);
        ValidationUtils.ValidateStringNotNullOrEmpty(outputPath);
        cancellationToken.ThrowIfCancellationRequested();

        var ciphertext = await File.ReadAllBytesAsync(inputPath, cancellationToken).ConfigureAwait(false);
        var plaintext = await Task.Run(() => Decrypt(ciphertext, cancellationToken), cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(outputPath, plaintext, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     Parses an age header from ciphertext.
    /// </summary>
    /// <param name="ciphertext">The ciphertext containing the header.</param>
    /// <returns>A tuple containing the parsed header and the payload start position.</returns>
    public static (Format.Header Header, long PayloadStart) ParseHeader(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        _logger.Value.LogTrace("=== AGE PARSE HEADER START ===");
        _logger.Value.LogTrace("Ciphertext length: {CiphertextLength} bytes", ciphertext.Length);

        // Find the header by searching for the MAC line pattern
        var ciphertextString = Encoding.UTF8.GetString(ciphertext);
        var lines = ciphertextString.Split('\n');

        var headerLines = new List<string>();
        var payloadStart = -1L;
        var currentPos = 0L;

        foreach (var line in lines)
        {
            headerLines.Add(line);
            _logger.Value.LogTrace("Read header line: '{Line}'", line);

            if (line.StartsWith("---"))
            {
                // The payload starts after the MAC line (including the newline)
                payloadStart = currentPos + line.Length + 1; // +1 for the newline
                _logger.Value.LogTrace("Found MAC line, payload starts at position: {PayloadStart}", payloadStart);
                break;
            }

            currentPos += line.Length + 1; // +1 for the newline
        }

        if (payloadStart == -1)
            throw new AgeFormatException("No MAC line found in age file");

        // Reconstruct the header string and parse it properly
        var headerString = string.Join("\n", headerLines);
        _logger.Value.LogTrace("Reconstructed header string: {HeaderString}", headerString);

        // Use Header.Decode to properly parse the header including stanza bodies
        var header = Header.Decode(headerString);
        _logger.Value.LogTrace("Successfully parsed header with {StanzaCount} stanzas", header.Stanzas.Count);

        _logger.Value.LogTrace("=== AGE PARSE HEADER END ===");
        return (header, payloadStart);
    }

    /// <summary>
    ///     Checks if the ciphertext is passphrase-encrypted.
    /// </summary>
    /// <param name="ciphertext">The ciphertext to check.</param>
    /// <returns>True if the ciphertext is passphrase-encrypted.</returns>
    public static bool IsPassphraseEncrypted(byte[] ciphertext)
    {
        try
        {
            var header = ParseHeader(ciphertext).Header;
            return header.Stanzas.Any(s => s.Type == "scrypt");
        }
        catch
        {
            return false;
        }
    }
}