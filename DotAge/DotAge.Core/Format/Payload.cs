using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Format;

/// <summary>
///     Represents the payload section of an age file, containing the encrypted data.
///     This implementation matches the age specification exactly.
/// </summary>
public class Payload
{
    private const int StreamKeySize = 32;
    private const string PayloadInfo = "payload";

    private static readonly Lazy<ILogger<Payload>> _logger = new(() => LoggerFactory.CreateLogger<Payload>());

    /// <summary>
    ///     Initializes a new payload with the given file key.
    /// </summary>
    /// <param name="fileKey">The file key (16 bytes).</param>
    public Payload(byte[] fileKey)
    {
        if (fileKey == null || fileKey.Length != CryptoConstants.FileKeySize)
            throw new AgeKeyException($"File key must be {CryptoConstants.FileKeySize} bytes");

        FileKey = fileKey;
        _logger.Value.LogTrace("Created payload with file key length: {FileKeyLength} bytes", fileKey.Length);
        _logger.Value.LogTrace("File key: {FileKey}", BitConverter.ToString(fileKey));
    }

    /// <summary>
    ///     Gets the file key used for this payload.
    /// </summary>
    public byte[] FileKey { get; }

    /// <summary>
    ///     Creates a writer for encrypting data to the payload.
    ///     Reference: https://github.com/FiloSottile/age/blob/main/age.go#L98 and
    ///     https://github.com/str4d/rage/blob/master/age-core/src/format.rs
    /// </summary>
    /// <param name="destination">The destination stream.</param>
    /// <returns>A stream writer that encrypts data using the chunked encryption scheme.</returns>
    public Stream CreateEncryptWriter(Stream destination)
    {
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));

        // Generate a random nonce and write it at the beginning of the payload
        // Reference: Go age.go#L98, Rust format.rs
        // Note: age uses streamNonceSize = 16, not chacha20poly1305.NonceSize = 12
        var nonce = RandomUtils.GenerateRandomBytes(CryptoConstants.StreamNonceSize);
        _logger.Value.LogTrace("Generated nonce: {Nonce}", BitConverter.ToString(nonce));

        destination.Write(nonce, 0, nonce.Length);

        // Derive the stream key and create the chunked writer
        // Reference: Go streamKey(fileKey, nonce), Rust stream_key
        var streamKey = DeriveStreamKey(FileKey, nonce);
        _logger.Value.LogTrace("Derived stream key: {StreamKey}", BitConverter.ToString(streamKey));

        // The chunked stream starts with an all-zero nonce and increments it internally
        return ChunkedStream.CreateWriter(streamKey, destination);
    }

    /// <summary>
    ///     Creates a reader for decrypting data from the payload.
    ///     Reference: https://github.com/FiloSottile/age/blob/main/age.go#L209 and
    ///     https://github.com/str4d/rage/blob/master/age-core/src/format.rs
    /// </summary>
    /// <param name="source">The source stream.</param>
    /// <returns>A stream reader that decrypts data using the chunked encryption scheme.</returns>
    public Stream CreateDecryptReader(Stream source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        // Read the nonce from the beginning of the payload
        // Reference: Go age.go#L209, Rust format.rs
        // Note: age uses streamNonceSize = 16, not chacha20poly1305.NonceSize = 12
        var nonce = new byte[CryptoConstants.StreamNonceSize];
        var bytesRead = source.Read(nonce, 0, nonce.Length);
        if (bytesRead != CryptoConstants.StreamNonceSize)
            throw new AgeDecryptionException("Failed to read nonce from payload");

        _logger.Value.LogTrace("Read nonce from source stream: {Nonce}", BitConverter.ToString(nonce));

        // Derive the stream key and create the chunked reader
        // Reference: Go streamKey(fileKey, nonce), Rust stream_key
        var streamKey = DeriveStreamKey(FileKey, nonce);
        _logger.Value.LogTrace("Derived stream key: {StreamKey}", BitConverter.ToString(streamKey));

        // The chunked stream starts with an all-zero nonce and increments it internally
        return ChunkedStream.CreateReader(streamKey, source);
    }

    /// <summary>
    ///     Encrypts data to a stream using the chunked encryption scheme.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="destination">The destination stream.</param>
    public void EncryptData(byte[] data, Stream destination)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));

        _logger.Value.LogTrace("Data to encrypt: {DataLength} bytes", data.Length);
        _logger.Value.LogTrace("Data (first 64 bytes): {DataPrefix}", BitConverter.ToString(data.Take(64).ToArray()));

        using (var writer = CreateEncryptWriter(destination))
        {
            writer.Write(data, 0, data.Length);
            writer.Close();
        }
    }

    /// <summary>
    ///     Decrypts data from a stream using the chunked encryption scheme.
    /// </summary>
    /// <param name="source">The source stream.</param>
    /// <returns>The decrypted data.</returns>
    public byte[] DecryptData(Stream source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        using (var reader = CreateDecryptReader(source))
        using (var memoryStream = new MemoryStream())
        {
            try
            {
                reader.CopyTo(memoryStream);
            }
            catch (IOException ex)
            {
                _logger.Value.LogTrace("IO error during chunked decryption: {Error}", ex.Message);
                throw new AgeDecryptionException("Error during chunked decryption", ex);
            }

            var result = memoryStream.ToArray();
            _logger.Value.LogTrace("Decrypted data: {ResultLength} bytes", result.Length);
            _logger.Value.LogTrace("Decrypted data (first 64 bytes): {ResultPrefix}",
                BitConverter.ToString(result.Take(64).ToArray()));
            return result;
        }
    }

    /// <summary>
    ///     Derives the stream key from file key and nonce using HKDF, matching age implementation exactly.
    ///     Reference: https://github.com/FiloSottile/age/blob/main/age.go#L112 and
    ///     https://github.com/str4d/rage/blob/master/age-core/src/format.rs
    /// </summary>
    /// <param name="fileKey">The file key.</param>
    /// <param name="nonce">The stream nonce (16 bytes).</param>
    /// <returns>The derived stream key.</returns>
    private static byte[] DeriveStreamKey(byte[] fileKey, byte[] nonce)
    {
        if (fileKey == null || fileKey.Length != CryptoConstants.FileKeySize)
            throw new AgeKeyException($"File key must be {CryptoConstants.FileKeySize} bytes");
        if (nonce == null || nonce.Length != CryptoConstants.StreamNonceSize)
            throw new AgeCryptoException($"Stream nonce must be {CryptoConstants.StreamNonceSize} bytes");

        _logger.Value.LogTrace("Deriving stream key using HKDF");
        _logger.Value.LogTrace("File key: {FileKey}", BitConverter.ToString(fileKey));
        _logger.Value.LogTrace("Nonce: {Nonce}", BitConverter.ToString(nonce));

        // Use HKDF with SHA256, fileKey as IKM (secret), nonce as salt, and payload info
        // Reference: Go hkdf.New(sha256.New, fileKey, nonce, []byte("payload")), Rust hkdf(salt, label, ikm)
        var streamKey = Hkdf.DeriveKey(fileKey, nonce, PayloadInfo, StreamKeySize);
        _logger.Value.LogTrace("Derived stream key: {StreamKey}", BitConverter.ToString(streamKey));

        return streamKey;
    }
}