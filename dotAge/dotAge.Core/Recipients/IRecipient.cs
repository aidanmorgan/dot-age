using System.Threading;
using System.Threading.Tasks;
using DotAge.Core.Format;

namespace DotAge.Core.Recipients
{
    /// <summary>
    /// Represents a recipient in the age encryption system.
    /// </summary>
    public interface IRecipient
    {
        /// <summary>
        /// Gets the type of the recipient.
        /// </summary>
        string Type { get; }

        /// <summary>
        /// Creates a stanza for the recipient.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <returns>A stanza containing the wrapped file key.</returns>
        Stanza CreateStanza(byte[] fileKey);

        /// <summary>
        /// Creates a stanza for the recipient asynchronously.
        /// </summary>
        /// <param name="fileKey">The file key to wrap.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a stanza with the wrapped file key.</returns>
        Task<Stanza> CreateStanzaAsync(byte[] fileKey, CancellationToken cancellationToken = default);

        /// <summary>
        /// Unwraps a file key from a stanza.
        /// </summary>
        /// <param name="stanza">The stanza containing the wrapped file key.</param>
        /// <returns>The unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
        byte[]? UnwrapKey(Stanza stanza);

        /// <summary>
        /// Unwraps a file key from a stanza asynchronously.
        /// </summary>
        /// <param name="stanza">The stanza containing the wrapped file key.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the unwrapped file key, or null if the recipient cannot unwrap the file key.</returns>
        Task<byte[]?> UnwrapKeyAsync(Stanza stanza, CancellationToken cancellationToken = default);
    }
}
