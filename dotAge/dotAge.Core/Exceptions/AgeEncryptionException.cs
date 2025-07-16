namespace DotAge.Core.Exceptions;

/// <summary>
///     Exception thrown when an error occurs during age encryption operations.
/// </summary>
public class AgeEncryptionException : AgeException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeEncryptionException" /> class.
    /// </summary>
    public AgeEncryptionException()
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeEncryptionException" /> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeEncryptionException(string message) : base(message)
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeEncryptionException" /> class with a specified error message
    ///     and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public AgeEncryptionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}