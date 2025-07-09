using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Format;

/// <summary>
///     Represents the header of an age-encrypted file.
/// </summary>
public class Header
{
    private static readonly ILogger<Header> _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<Header>();

    // The age file format version
    public const string Version = "age-encryption.org/v1";

    /// <summary>
    ///     Creates a new header with the specified recipient stanzas.
    /// </summary>
    /// <param name="stanzas">The recipient stanzas.</param>
    public Header(IEnumerable<Stanza>? stanzas = null)
    {
        if (stanzas != null) Stanzas.AddRange(stanzas);
    }

    // The list of recipient stanzas
    public List<Stanza> Stanzas { get; } = new();

    // The MAC (Message Authentication Code) of the header
    public byte[]? Mac { get; set; }

    /// <summary>
    ///     Encodes the header as a string (without MAC).
    /// </summary>
    /// <returns>The encoded header as a string.</returns>
    public string EncodeWithoutMac()
    {
        var sb = new StringBuilder();

        // Add the version line
        sb.Append(Version);
        sb.Append("\n");

        // Add the recipient stanzas
        foreach (var stanza in Stanzas) 
        {
            var stanzaEncoded = stanza.Encode();
            sb.Append(stanzaEncoded);
            _logger.LogTrace("Added stanza of type {StanzaType}: {StanzaEncoded}", stanza.Type, stanzaEncoded);
        }

        // Add the MAC prefix (without the MAC value)
        sb.Append("---");
        _logger.LogTrace("Added MAC prefix: ---");

        var result = sb.ToString();
        _logger.LogTrace("Header encoded without MAC: {HeaderLength} characters", result.Length);
        _logger.LogTrace("Header content: {HeaderContent}", result);
        return result;
    }

    /// <summary>
    ///     Encodes the header as a string.
    /// </summary>
    /// <returns>The encoded header as a string.</returns>
    public string Encode()
    {
        var sb = new StringBuilder();

        // Add the version line
        sb.Append(Version);
        sb.Append("\n");

        // Add the recipient stanzas
        foreach (var stanza in Stanzas) 
        {
            var stanzaEncoded = stanza.Encode();
            sb.Append(stanzaEncoded);
            _logger.LogTrace("Added stanza of type {StanzaType}: {StanzaEncoded}", stanza.Type, stanzaEncoded);
        }

        // Add the MAC line if available
        if (Mac != null)
        {
            // Enforce MAC is 32 bytes (age/rage compatibility: 32 bytes = 43 base64 chars, unpadded)
            if (Mac.Length != 32)
                throw new AgeFormatException(
                    $"MAC must be 32 bytes (got {Mac.Length}) for age/rage compatibility");
            
            _logger.LogTrace("MAC value: {MacHex}", BitConverter.ToString(Mac));
            
            // Use canonical unpadded base64
            var macBase64 = Base64Utils.EncodeToString(Mac);
            sb.Append($"--- {macBase64}\n");
            _logger.LogTrace("Added MAC line: --- {MacBase64}", macBase64);
        }
        else
        {
            sb.Append("---\n");
            _logger.LogTrace("Added empty MAC line: ---");
        }

        var result = sb.ToString();
        _logger.LogTrace("Header encoded with MAC: {HeaderLength} characters", result.Length);
        _logger.LogTrace("Header content: {HeaderContent}", result);
        return result;
    }

    /// <summary>
    ///     Calculates the MAC for this header using the specified file key.
    /// </summary>
    /// <param name="fileKey">The file key to use for MAC calculation.</param>
    public void CalculateMac(byte[] fileKey)
    {
        if (fileKey == null || fileKey.Length != 16)
            throw new AgeKeyException("File key must be 16 bytes");

        _logger.LogTrace("Calculating header MAC");
        _logger.LogTrace("File key: {FileKeyHex}", BitConverter.ToString(fileKey));

        // Derive the MAC key using HKDF
        var macKey = Hkdf.DeriveKey(fileKey, new byte[0], "header", 32);
        _logger.LogTrace("Derived MAC key: {MacKeyHex}", BitConverter.ToString(macKey));

        // Calculate HMAC-SHA-256 over the header up to and including "---"
        var headerWithoutMac = EncodeWithoutMac();
        var headerBytes = Encoding.ASCII.GetBytes(headerWithoutMac);
        _logger.LogTrace("Header bytes for MAC calculation: {HeaderBytesHex}", BitConverter.ToString(headerBytes));

        using var hmac = new HMACSHA256(macKey);
        Mac = hmac.ComputeHash(headerBytes);
        _logger.LogTrace("Calculated MAC: {MacHex}", BitConverter.ToString(Mac));
    }

    /// <summary>
    ///     Calculates the MAC for this header using the specified file key and returns it.
    /// </summary>
    /// <param name="fileKey">The file key to use for MAC calculation.</param>
    /// <returns>The calculated MAC.</returns>
    public byte[] CalculateMacAndReturn(byte[] fileKey)
    {
        if (fileKey == null || fileKey.Length != 16)
            throw new AgeKeyException("File key must be 16 bytes");

        _logger.LogTrace("Calculating header MAC and returning");
        _logger.LogTrace("File key: {FileKeyHex}", BitConverter.ToString(fileKey));

        // Derive the MAC key using HKDF
        var macKey = Hkdf.DeriveKey(fileKey, new byte[0], "header", 32);
        _logger.LogTrace("Derived MAC key: {MacKeyHex}", BitConverter.ToString(macKey));

        // Calculate HMAC-SHA-256 over the header up to and including "---"
        var headerWithoutMac = EncodeWithoutMac();
        var headerBytes = Encoding.ASCII.GetBytes(headerWithoutMac);
        _logger.LogTrace("Header bytes for MAC calculation: {HeaderBytesHex}", BitConverter.ToString(headerBytes));

        using var hmac = new HMACSHA256(macKey);
        var mac = hmac.ComputeHash(headerBytes);
        _logger.LogTrace("Calculated MAC: {MacHex}", BitConverter.ToString(mac));
        return mac;
    }

    /// <summary>
    ///     Decodes a header from a string.
    /// </summary>
    /// <param name="encoded">The encoded header as a string.</param>
    /// <returns>The decoded header.</returns>
    public static Header Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded)) throw new AgeFormatException("Encoded header cannot be null or empty");

        var lines = encoded.Split(new[] { "\n" }, StringSplitOptions.None);

        if (lines.Length < 1)
            throw new AgeFormatException("Invalid header format: empty header");

        if (lines[0] != Version)
            throw new AgeFormatException($"Invalid header format: expected version {Version}, got {lines[0]}");

        var header = new Header();

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];

            // Skip empty lines
            if (string.IsNullOrEmpty(line))
                continue;

            // Check if this is a MAC line
            if (line.StartsWith("---"))
            {
                var macBase64 = line.Substring(3).Trim();
                if (!string.IsNullOrEmpty(macBase64))
                {
                    var mac = Base64Utils.DecodeString(macBase64);
                    // Enforce MAC is 32 bytes (age/rage compatibility)
                    if (mac.Length != 32)
                        throw new AgeFormatException(
                            $"MAC must be 32 bytes (got {mac.Length}) for age/rage compatibility");
                    header.Mac = mac;
                }

                break;
            }

            // Check if this is a new stanza
            if (line.StartsWith("->"))
            {
                // Parse the stanza type and arguments
                var stanzaContent = line.Substring(2).Trim();
                var parts = stanzaContent.Split(' ', 2);
                var stanzaType = parts[0];
                var stanzaArgs = parts.Length > 1 ? parts[1] : string.Empty;

                // Read the body lines until the next stanza or MAC line
                var bodyLines = new List<string>();
                while (i + 1 < lines.Length && !lines[i + 1].StartsWith("->") && !lines[i + 1].StartsWith("---"))
                {
                    i++;
                    if (!string.IsNullOrEmpty(lines[i])) bodyLines.Add(lines[i]);
                }

                // Use Stanza.Parse to construct the stanza
                var stanzaParsed = Stanza.Parse(stanzaType, new[] { stanzaArgs }.Concat(bodyLines));
                header.Stanzas.Add(stanzaParsed);
            }
        }

        return header;
    }
}