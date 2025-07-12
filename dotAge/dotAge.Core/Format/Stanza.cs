using System.Text;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Format;

/// <summary>
///     Represents a recipient stanza in the age file format.
/// </summary>
public class Stanza
{
    private static readonly Lazy<ILogger<Stanza>> _logger = new Lazy<ILogger<Stanza>>(() => DotAge.Core.Logging.LoggerFactory.CreateLogger<Stanza>());

    /// <summary>
    ///     Creates a new stanza with the specified type, arguments, and body.
    /// </summary>
    /// <param name="type">The type of the stanza.</param>
    /// <param name="arguments">The arguments of the stanza.</param>
    /// <param name="body">The body of the stanza as raw bytes.</param>
    public Stanza(string type, IEnumerable<string>? arguments = null, byte[]? body = null)
    {
        if (string.IsNullOrEmpty(type))
            throw new AgeFormatException("Stanza type cannot be null or empty");

        Type = type;

        if (arguments != null) Arguments.AddRange(arguments);

        if (body != null) Body = body;
    }

    // The type of the stanza (e.g., "X25519", "scrypt")
    public string Type { get; }

    // The arguments of the stanza
    public List<string> Arguments { get; } = new();

    // The body of the stanza (raw bytes, not base64 strings)
    public byte[] Body { get; set; } = new byte[0];

    /// <summary>
    ///     Creates a new stanza by parsing the specified raw text lines.
    /// </summary>
    /// <param name="type">The type of the stanza.</param>
    /// <param name="rawTextLines">The raw text lines to parse.</param>
    /// <returns>A new stanza.</returns>
    public static Stanza Parse(string type, IEnumerable<string> rawTextLines)
    {
        if (string.IsNullOrEmpty(type))
            throw new AgeFormatException("Stanza type cannot be null or empty");

        _logger.Value.LogTrace("=== STANZA PARSE START ===");
        _logger.Value.LogTrace("Stanza type: '{Type}'", type);

        if (rawTextLines == null)
        {
            _logger.Value.LogTrace("Raw text lines is null, returning empty stanza");
            return new Stanza(type);
        }

        var linesList = rawTextLines.ToList();
        _logger.Value.LogTrace("Raw text lines count: {LineCount}", linesList.Count);
        for (int idx = 0; idx < linesList.Count; idx++)
        {
            _logger.Value.LogTrace("Raw line {Index}: '{Line}'", idx, linesList[idx]);
        }

        var arguments = new List<string>();
        var bodyLines = new List<string>();

        // The first line contains the arguments
        if (linesList.Count > 0)
        {
            var firstLine = linesList[0];
            _logger.Value.LogTrace("First line: '{FirstLine}'", firstLine);

            // Check if the first line is the type (which would be the case if this is a stanza header line)
            if (firstLine.StartsWith(type))
            {
                _logger.Value.LogTrace("First line starts with type '{Type}'", type);
                // Extract arguments from the first line after the type
                var argsString = firstLine.Substring(type.Length).Trim();
                var args = argsString.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                arguments.AddRange(args);
                _logger.Value.LogTrace("Extracted arguments from type-prefixed line: {Arguments}", string.Join(", ", args));
            }
            else
            {
                _logger.Value.LogTrace("First line does not start with type '{Type}'", type);
                // If the first line doesn't start with the type, it contains the arguments
                var args = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                arguments.AddRange(args);
                _logger.Value.LogTrace("Extracted arguments from standalone line: {Arguments}", string.Join(", ", args));
            }

            // The rest of the lines are the body
            if (linesList.Count > 1) 
            {
                bodyLines.AddRange(linesList.Skip(1));
                _logger.Value.LogTrace("Body lines count: {BodyLineCount}", bodyLines.Count);
                for (int idx = 0; idx < bodyLines.Count; idx++)
                {
                    _logger.Value.LogTrace("Body line {Index}: '{Line}'", idx, bodyLines[idx]);
                }
            }
            else
            {
                _logger.Value.LogTrace("No body lines (only first line present)");
            }
        }

        // Decode the base64 body lines
        _logger.Value.LogTrace("Calling DecodeBase64Lines with {BodyLineCount} lines", bodyLines.Count);
        var bodyBytes = DecodeBase64Lines(bodyLines);
        _logger.Value.LogTrace("Decoded body bytes: {BodyBytesLength} bytes", bodyBytes.Length);

        _logger.Value.LogTrace("=== STANZA PARSE END ===");
        return new Stanza(type, arguments, bodyBytes);
    }

    /// <summary>
    ///     Encodes the stanza as a string.
    /// </summary>
    /// <returns>The encoded stanza as a string.</returns>
    public string Encode()
    {

        var sb = new StringBuilder();

        // Add the stanza type line
        sb.Append("-> ");
        sb.Append(Type);

        // Add the arguments
        if (Arguments.Count > 0)
        {
            sb.Append(" ");
            sb.Append(string.Join(" ", Arguments));
        }

        // Add the line ending after type and arguments
        sb.Append("\n");

        // Add the body as base64 wrapped at 64 columns
        if (Body.Length > 0)
        {
            var base64 = Base64Utils.EncodeToString(Body);
            _logger.Value.LogTrace("Body base64 length: {BodyBase64Length} characters", base64.Length);

            // Wrap base64 at 64 columns as required by age specification
            var wrappedBase64 = Base64Utils.WrapBase64(base64, 64);
            sb.Append(wrappedBase64);
            // Add final newline after the body
            sb.Append("\n");
        }

        return sb.ToString();
    }


    /// <summary>
    ///     Decodes base64 lines to raw bytes.
    /// </summary>
    private static byte[] DecodeBase64Lines(IEnumerable<string> lines)
    {
        var bodyBytes = new List<byte>();

        foreach (var line in lines)
        {
            var trimmedLine = line.Trim();
            if (string.IsNullOrEmpty(trimmedLine))
                continue;

            _logger.Value.LogTrace("Decoding base64 line: {Line}", trimmedLine);

            try
            {
                var lineBytes = Base64Utils.DecodeString(trimmedLine);
                bodyBytes.AddRange(lineBytes);
                _logger.Value.LogTrace("Decoded {LineByteCount} bytes from line", lineBytes.Length);
            }
            catch (FormatException ex)
            {
                _logger.Value.LogTrace("Invalid base64 in stanza body: {Line} - {Error}", trimmedLine, ex.Message);
                throw new AgeFormatException($"Invalid base64 in stanza body: {trimmedLine} - {ex.Message}", ex);
            }
        }

        var result = bodyBytes.ToArray();
        _logger.Value.LogTrace("Total decoded body bytes: {TotalBytes}", result.Length);
        return result;
    }
}