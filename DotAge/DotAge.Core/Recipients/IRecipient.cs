using DotAge.Core.Format;

namespace DotAge.Core.Recipients;

/// <summary>
///     Represents a recipient in the age encryption system.
/// </summary>
public interface IRecipient
{
    /// <summary>
    ///     Gets the type of the recipient.
    /// </summary>
    string Type { get; }

    /// <summary>
    ///     Creates a stanza for the recipient.
    /// </summary>
    /// <param name="fileKey">The file key to wrap.</param>
    /// <returns>A stanza containing the wrapped file key.</returns>
    Stanza CreateStanza(byte[] fileKey);

    /// <summary>
    ///     Unwraps a file key from a stanza.
    /// </summary>
    /// <param name="stanza">The stanza containing the wrapped file key.</param>
    /// <returns>The unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
    byte[]? UnwrapKey(Stanza stanza);

    /// <summary>
    ///     Returns true if this recipient supports the given stanza type.
    /// </summary>
    bool SupportsStanzaType(string stanzaType);
}