using System.Runtime.CompilerServices;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for validation operations used across the codebase.
/// </summary>
public static class ValidationUtils
{
    private static readonly Lazy<ILogger> Logger = new(() => LoggerFactory.CreateLogger(nameof(ValidationUtils)));

    /// <summary>
    ///     Validates a file key.
    /// </summary>
    /// <param name="fileKey">The file key to validate.</param>
    /// <param name="paramName">The parameter name for exception reporting.</param>
    /// <exception cref="AgeKeyException">Thrown when the file key is invalid.</exception>
    /// <exception cref="ArgumentNullException">Thrown when the file key is null.</exception>
    public static void ValidateFileKey(byte[]? fileKey,
        [CallerArgumentExpression(nameof(fileKey))] string? paramName = null)
    {
        ArgumentNullException.ThrowIfNull(fileKey, paramName);

        Logger.Value.LogTrace("Validating file key of length {FileKeyLength}", fileKey.Length);

        if (fileKey.Length == CryptoConstants.FileKeySize) return;

        Logger.Value.LogTrace("File key validation failed: expected {ExpectedFileKeySize} bytes, got {FileKeyLength}",
            CryptoConstants.FileKeySize, fileKey.Length);
        throw new AgeKeyException($"File key must be {CryptoConstants.FileKeySize} bytes");
    }

    /// <summary>
    ///     Validates a stanza for X25519 recipient.
    /// </summary>
    /// <param name="stanza">The stanza to validate.</param>
    /// <param name="expectedType">The expected stanza type.</param>
    /// <param name="expectedArgumentCount">The expected number of arguments.</param>
    /// <exception cref="ArgumentNullException">Thrown when the stanza is null.</exception>
    /// <exception cref="AgeFormatException">Thrown when the stanza is invalid.</exception>
    public static void ValidateStanza(Stanza? stanza, string expectedType, int expectedArgumentCount)
    {
        ArgumentNullException.ThrowIfNull(stanza);
        ArgumentException.ThrowIfNullOrEmpty(expectedType);
        ArgumentOutOfRangeException.ThrowIfNegative(expectedArgumentCount);

        if (!string.Equals(stanza.Type, expectedType, StringComparison.Ordinal))
        {
            Logger.Value.LogTrace("Stanza type validation failed: expected '{ExpectedType}', got '{StanzaType}'",
                expectedType, stanza.Type);
            throw new AgeFormatException($"Expected stanza type '{expectedType}', got '{stanza.Type}'");
        }

        if (stanza.Arguments.Count != expectedArgumentCount)
        {
            Logger.Value.LogTrace(
                "Stanza argument count validation failed: expected {ExpectedArgumentCount}, got {ArgumentCount}",
                expectedArgumentCount, stanza.Arguments.Count);
            throw new AgeFormatException($"Expected {expectedArgumentCount} arguments, got {stanza.Arguments.Count}");
        }

        if (stanza.Body.Length != 0) return;

        Logger.Value.LogTrace("Stanza body validation failed: body is empty");
        throw new AgeFormatException("Stanza body cannot be empty");
    }

    /// <summary>
    ///     Validates that a string parameter is not null or empty using modern C# validation.
    /// </summary>
    /// <param name="value">The string value to validate.</param>
    /// <param name="paramName">The parameter name for exception reporting.</param>
    /// <exception cref="ArgumentException">Thrown when the value is null or empty.</exception>
    public static void ValidateStringNotNullOrEmpty(string? value,
        [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(value, paramName);
    }

    /// <summary>
    ///     Validates that a string parameter is not null, empty, or whitespace using modern C# validation.
    /// </summary>
    /// <param name="value">The string value to validate.</param>
    /// <param name="paramName">The parameter name for exception reporting.</param>
    /// <exception cref="ArgumentException">Thrown when the value is null, empty, or whitespace.</exception>
    public static void ValidateStringNotNullOrWhiteSpace(string? value,
        [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, paramName);
    }
}