namespace DotAge.Core.Exceptions;

/// <summary>
///     Exception thrown when an error occurs during age key operations (generation, parsing, validation).
/// </summary>
public class AgeKeyException : AgeException
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeKeyException" /> class.
    /// </summary>
    public AgeKeyException()
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeKeyException" /> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public AgeKeyException(string message) : base(message)
    {
    }

    /// <summary>
    ///     Initializes a new instance of the <see cref="AgeKeyException" /> class with a specified error message
    ///     and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public AgeKeyException(string message, Exception innerException) : base(message, innerException)
    {
    }
}