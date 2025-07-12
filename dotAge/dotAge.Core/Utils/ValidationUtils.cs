using DotAge.Core.Format;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for validation operations used across the codebase.
/// </summary>
public static class ValidationUtils
{
    private static readonly Lazy<ILogger> Logger = new Lazy<ILogger>(() => DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(ValidationUtils)));

    /// <summary>
    ///     Validates a file key.
    /// </summary>
    /// <param name="fileKey">The file key to validate.</param>
    /// <exception cref="AgeKeyException">Thrown when the file key is invalid.</exception>
    /// <exception cref="ArgumentNullException">Thrown when the file key is null.</exception>
    public static void ValidateFileKey(byte[] fileKey)
    {
        ArgumentNullException.ThrowIfNull(fileKey);

        Logger.Value.LogTrace("Validating file key of length {FileKeyLength}", fileKey.Length);

        if (fileKey.Length == 16) return;
        
        Logger.Value.LogTrace("File key validation failed: expected 16 bytes, got {FileKeyLength}", fileKey.Length);
        throw new AgeKeyException("File key must be 16 bytes");
    }

    /// <summary>
    ///     Validates a stanza for X25519 recipient.
    /// </summary>
    /// <param name="stanza">The stanza to validate.</param>
    /// <param name="expectedType">The expected stanza type.</param>
    /// <param name="expectedArgumentCount">The expected number of arguments.</param>
    /// <exception cref="ArgumentNullException">Thrown when the stanza is null.</exception>
    /// <exception cref="AgeFormatException">Thrown when the stanza is invalid.</exception>
    public static void ValidateStanza(Stanza stanza, string expectedType, int expectedArgumentCount)
    {
        ArgumentNullException.ThrowIfNull(stanza);
        
        if (!string.Equals(stanza.Type, expectedType, StringComparison.Ordinal))
        {
            Logger.Value.LogTrace("Stanza type validation failed: expected '{ExpectedType}', got '{StanzaType}'", 
                expectedType, stanza.Type);
            throw new AgeFormatException($"Expected stanza type '{expectedType}', got '{stanza.Type}'");
        }

        if (stanza.Arguments.Count != expectedArgumentCount)
        {
            Logger.Value.LogTrace("Stanza argument count validation failed: expected {ExpectedArgumentCount}, got {ArgumentCount}", 
                expectedArgumentCount, stanza.Arguments.Count);
            throw new AgeFormatException($"Expected {expectedArgumentCount} arguments, got {stanza.Arguments.Count}");
        }

        if (stanza.Body.Length != 0) return;
        
        Logger.Value.LogTrace("Stanza body validation failed: body is empty");
        throw new AgeFormatException("Stanza body cannot be empty");
    }
} 