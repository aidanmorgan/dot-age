namespace DotAge.Core.Exceptions;

/// <summary>
///     Exception thrown when an error occurs during age decryption operations.
/// </summary>
public class AgeDecryptionException : AgeException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeDecryptionException" /> class.
    /// </summary>
    public AgeDecryptionException()
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeDecryptionException" /> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeDecryptionException(string message) : base(message)
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeDecryptionException" /> class with a specified error message
    ///     and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public AgeDecryptionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}