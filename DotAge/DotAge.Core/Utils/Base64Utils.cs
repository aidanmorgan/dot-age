using System.Text;
using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Utils;

/// <summary>
///     Provides base64 utilities that match the age specification (unpadded base64).
/// </summary>
public static class Base64Utils
{
    private static readonly ILogger Logger = LoggerFactory.CreateLogger(nameof(Base64Utils));

    /// <summary>
    ///     Encodes bytes to unpadded base64 string (equivalent to base64.RawStdEncoding in Go).
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <returns>The unpadded base64 string.</returns>
    public static string EncodeToString(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        Logger.LogTrace("Encoding {DataLength} bytes to base64", data.Length);

        var result = Convert.ToBase64String(data).TrimEnd('=');

        return result;
    }

    /// <summary>
    ///     Decodes an unpadded base64 string to bytes (equivalent to base64.RawStdEncoding.Strict() in Go).
    /// </summary>
    /// <param name="s">The base64 string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="FormatException">Thrown when the input is not valid base64.</exception>
    public static byte[] DecodeString(string s)
    {
        if (s == null)
            throw new ArgumentNullException(nameof(s));

        // Check for newline characters (not allowed in age format)
        if (s.Contains('\n') || s.Contains('\r'))
        {
            Logger.LogTrace("Base64 string contains newline characters, which is not allowed");
            throw new AgeFormatException("unexpected newline character");
        }

        // Add padding if needed
        var padded = s;
        while (padded.Length % 4 != 0)
            padded += "=";

        try
        {
            var result = Convert.FromBase64String(padded);
            return result;
        }
        catch (FormatException ex)
        {
            Logger.LogTrace("Invalid base64 string: {Error}", ex.Message);
            throw new AgeFormatException($"Invalid base64 string: {ex.Message}", ex);
        }
    }

    /// <summary>
    ///     Wraps base64 string at specified column width, matching age's WrappedBase64Encoder behavior.
    /// </summary>
    /// <param name="base64">The base64 string to wrap.</param>
    /// <param name="columnsPerLine">The number of columns per line (64 for age).</param>
    /// <returns>The wrapped base64 string.</returns>
    public static string WrapBase64(string base64, int columnsPerLine = 64)
    {
        if (base64 == null)
            throw new ArgumentNullException(nameof(base64));

        if (columnsPerLine <= 0)
            throw new AgeFormatException("columnsPerLine must be positive");

        Logger.LogTrace("Wrapping base64 string of length {Base64Length} at {ColumnsPerLine} columns per line",
            base64.Length, columnsPerLine);

        if (base64.Length <= columnsPerLine)
        {
            Logger.LogTrace("Base64 string fits in single line, returning as-is");
            return base64;
        }

        var lineCount = (base64.Length + columnsPerLine - 1) / columnsPerLine;
        var totalLength = base64.Length + lineCount - 1; // +1 newline per line except last

        var result = string.Create(totalLength, (base64, columnsPerLine), static (span, state) =>
        {
            var (source, columns) = state;
            var sourceSpan = source.AsSpan();
            var pos = 0;

            for (var i = 0; i < sourceSpan.Length; i += columns)
            {
                var chunkSize = Math.Min(columns, sourceSpan.Length - i);
                sourceSpan.Slice(i, chunkSize).CopyTo(span.Slice(pos));
                pos += chunkSize;

                if (i + columns < sourceSpan.Length)
                    span[pos++] = '\n';
            }
        });

        Logger.LogTrace("Wrapped base64 result: {ResultLength} characters", result.Length);
        return result;
    }
}