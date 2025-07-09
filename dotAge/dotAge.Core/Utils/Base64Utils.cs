using System.Text;
using DotAge.Core.Exceptions;

namespace DotAge.Core.Utils;

/// <summary>
///     Provides base64 utilities that match the age specification (unpadded base64).
/// </summary>
public static class Base64Utils
{
    /// <summary>
    ///     Encodes bytes to unpadded base64 string (equivalent to base64.RawStdEncoding in Go).
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <returns>The unpadded base64 string.</returns>
    public static string EncodeToString(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        return Convert.ToBase64String(data).TrimEnd('=');
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
            throw new AgeFormatException("unexpected newline character");

        // Add padding if needed
        var padded = s;
        while (padded.Length % 4 != 0)
            padded += "=";

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
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

        var sb = new StringBuilder();
        for (var i = 0; i < base64.Length; i += columnsPerLine)
        {
            var line = base64.Substring(i, Math.Min(columnsPerLine, base64.Length - i));
            sb.Append(line);
            if (i + columnsPerLine < base64.Length) sb.Append('\n');
        }

        return sb.ToString();
    }
}