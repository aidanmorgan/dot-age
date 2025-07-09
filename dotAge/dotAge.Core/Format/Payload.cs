using System.Security.Cryptography;
using DotAge.Core.Crypto;
using DotAge.Core.Utils;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Format;

/// <summary>
///     Represents the payload section of an age file, containing the encrypted data.
///     This implementation matches the age specification exactly.
/// </summary>
public class Payload
{
    private static readonly ILogger<Payload> _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<Payload>();

    /// <summary>
    ///     Initializes a new payload with the given file key.
    /// </summary>
    /// <param name="fileKey">The file key (16 bytes).</param>
    public Payload(byte[] fileKey)
    {
        if (fileKey == null || fileKey.Length != 16)
            throw new AgeKeyException("File key must be 16 bytes");

        FileKey = fileKey;
        _logger.LogTrace("Created payload with file key: {FileKeyHex}", BitConverter.ToString(fileKey));
    }

    /// <summary>
    ///     Gets the file key used for this payload.
    /// </summary>
    public byte[] FileKey { get; }

    /// <summary>
    ///     Creates a writer for encrypting data to the payload.
    /// </summary>
    /// <param name="destination">The destination stream.</param>
    /// <returns>A stream writer that encrypts data using the chunked encryption scheme.</returns>
    public Stream CreateEncryptWriter(Stream destination)
    {
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));

        // Generate a random nonce (16 bytes) and write it at the beginning of the payload
        var nonce = RandomUtils.GenerateRandomBytes(16);
        _logger.LogTrace("Generated nonce: {NonceHex}", BitConverter.ToString(nonce));

        destination.Write(nonce, 0, nonce.Length);

        // Derive the stream key and create the chunked writer
        var streamKey = DeriveStreamKey(FileKey, nonce);
        _logger.LogTrace("Derived stream key: {StreamKeyHex}", BitConverter.ToString(streamKey));

        return ChunkedStream.CreateWriter(streamKey, destination);
    }

    /// <summary>
    ///     Creates a reader for decrypting data from the payload.
    /// </summary>
    /// <param name="source">The source stream.</param>
    /// <returns>A stream reader that decrypts data using the chunked encryption scheme.</returns>
    public Stream CreateDecryptReader(Stream source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        // Read the nonce from the beginning of the payload (16 bytes)
        var nonce = new byte[16];
        var bytesRead = source.Read(nonce, 0, nonce.Length);
        if (bytesRead != 16)
            throw new AgeDecryptionException("Failed to read nonce from payload");

        _logger.LogTrace("Read nonce from source stream: {NonceHex}", BitConverter.ToString(nonce));

        // Derive the stream key and create the chunked reader
        var streamKey = DeriveStreamKey(FileKey, nonce);
        _logger.LogTrace("Derived stream key: {StreamKeyHex}", BitConverter.ToString(streamKey));

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

        _logger.LogTrace("Data to encrypt: {DataHex}", BitConverter.ToString(data));

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
                _logger.LogTrace("IO error during chunked decryption: {Error}", ex.Message);
                throw new AgeDecryptionException("Error during chunked decryption", ex);
            }

            var result = memoryStream.ToArray();
            _logger.LogTrace("Decrypted data: {ResultHex}", BitConverter.ToString(result));
            return result;
        }
    }

    /// <summary>
    ///     Derives the stream key from file key and nonce using HKDF, matching age implementation exactly.
    /// </summary>
    /// <param name="fileKey">The file key (16 bytes).</param>
    /// <param name="nonce">The stream nonce (16 bytes).</param>
    /// <returns>The derived stream key (32 bytes).</returns>
    private static byte[] DeriveStreamKey(byte[] fileKey, byte[] nonce)
    {
        if (fileKey == null || fileKey.Length != 16)
            throw new AgeKeyException("File key must be 16 bytes");
        if (nonce == null || nonce.Length != 16)
            throw new AgeCryptoException("Nonce must be 16 bytes");

        _logger.LogTrace("Deriving stream key using HKDF");
        _logger.LogTrace("File key: {FileKeyHex}", BitConverter.ToString(fileKey));
        _logger.LogTrace("Nonce: {NonceHex}", BitConverter.ToString(nonce));

        // Use HKDF with SHA256, fileKey as IKM (secret), nonce as salt, and "payload" as info
        // This matches the age implementation: hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
        var streamKey = Hkdf.DeriveKey(fileKey, nonce, "payload", 32);
        _logger.LogTrace("Derived stream key: {StreamKeyHex}", BitConverter.ToString(streamKey));

        return streamKey;
    }
}