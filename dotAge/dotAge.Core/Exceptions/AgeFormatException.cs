namespace DotAge.Core.Exceptions;

/// <summary>
///     Exception thrown when an error occurs during age format operations (parsing, encoding, validation).
/// </summary>
public class AgeFormatException : AgeException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeFormatException" /> class.
    /// </summary>
    public AgeFormatException()
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeFormatException" /> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeFormatException(string message) : base(message)
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeFormatException" /> class with a specified error message
    ///     and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public AgeFormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}