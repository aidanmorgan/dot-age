using System.Security.Cryptography;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides chunked encryption/decryption functionality matching the age implementation.
/// </summary>
public static class ChunkedStream
{
    private static readonly ILogger Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(ChunkedStream));

    public const int ChunkSize = 64 * 1024; // 64KB
    internal const int NonceSize = 12; // ChaCha20-Poly1305 nonce size
    internal const byte LastChunkFlag = 0x01;
    internal const int EncChunkSize = ChunkSize + 16; // ChunkSize + ChaCha20-Poly1305 overhead

    /// <summary>
    ///     Creates a new ChunkedStreamWriter for encryption.
    /// </summary>
    /// <param name="key">The encryption key.</param>
    /// <param name="destination">The destination stream.</param>
    /// <returns>A new ChunkedStreamWriter.</returns>
    public static ChunkedStreamWriter CreateWriter(byte[] key, Stream destination)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (destination == null) throw new ArgumentNullException(nameof(destination));
        if (key.Length != ChaCha20Poly1305.KeySize)
            throw new AgeCryptoException($"Key must be {ChaCha20Poly1305.KeySize} bytes");

        Logger.LogTrace("Creating ChunkedStreamWriter with key: {KeyHex}", BitConverter.ToString(key));
        return new ChunkedStreamWriter(key, destination);
    }

    /// <summary>
    ///     Creates a new ChunkedStreamReader for decryption.
    /// </summary>
    /// <param name="key">The decryption key.</param>
    /// <param name="source">The source stream.</param>
    /// <returns>A new ChunkedStreamReader.</returns>
    public static ChunkedStreamReader CreateReader(byte[] key, Stream source)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (source == null) throw new ArgumentNullException(nameof(source));
        if (key.Length != ChaCha20Poly1305.KeySize)
            throw new AgeCryptoException($"Key must be {ChaCha20Poly1305.KeySize} bytes");

        Logger.LogTrace("Creating ChunkedStreamReader with key: {KeyHex}", BitConverter.ToString(key));
        return new ChunkedStreamReader(key, source);
    }

    /// <summary>
    ///     Increments the nonce counter (first 11 bytes) for the next chunk, matching age's incNonce.
    /// </summary>
    /// <param name="nonce">The nonce to increment.</param>
    internal static void IncrementNonce(byte[] nonce)
    {
        // Increment from right to left, stopping at first non-zero (matching age's incNonce)
        for (var i = nonce.Length - 2; i >= 0; i--)
        {
            nonce[i]++;
            if (nonce[i] != 0)
                break;
            if (i == 0)
                throw new AgeCryptoException("stream: chunk counter wrapped around");
        }
    }

    /// <summary>
    ///     Sets the last chunk flag in the nonce, matching age's setLastChunkFlag.
    /// </summary>
    /// <param name="nonce">The nonce to modify.</param>
    internal static void SetLastChunkFlag(byte[] nonce)
    {
        nonce[^1] = LastChunkFlag;
    }

    /// <summary>
    ///     Checks if the nonce is all zeros, matching age's nonceIsZero.
    /// </summary>
    /// <param name="nonce">The nonce to check.</param>
    /// <returns>True if the nonce is all zeros.</returns>
    internal static bool IsNonceZero(byte[] nonce)
    {
        for (var i = 0; i < nonce.Length; i++)
            if (nonce[i] != 0)
                return false;
        return true;
    }
}

/// <summary>
///     Writer for chunked encryption, matching age implementation.
/// </summary>
public class ChunkedStreamWriter : Stream
{
    private static readonly ILogger<ChunkedStreamWriter> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<ChunkedStreamWriter>();

    private readonly byte[] _buffer;
    private readonly Stream _destination;
    private readonly byte[] _key;
    private readonly byte[] _nonce;
    private int _bufferLength;
    private bool _disposed;

    public ChunkedStreamWriter(byte[] key, Stream destination)
    {
        _key = key;
        _destination = destination;
        _buffer = new byte[ChunkedStream.EncChunkSize]; // Single buffer like age
        _nonce = new byte[12]; // All zeros initially
        _bufferLength = 0;
        
        Logger.LogTrace("ChunkedStreamWriter initialized with key: {KeyHex}", BitConverter.ToString(key));
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (buffer == null) throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException();
        if (count == 0)
            return;

        Logger.LogTrace("Writing {Count} bytes to chunked stream", count);

        while (count > 0)
        {
            var available = ChunkedStream.ChunkSize - _bufferLength;
            var toWrite = Math.Min(available, count);

            Array.Copy(buffer, offset, _buffer, _bufferLength, toWrite);
            _bufferLength += toWrite;
            offset += toWrite;
            count -= toWrite;


            if (_bufferLength == ChunkedStream.ChunkSize && count > 0) FlushChunk(false);
        }
    }

    public override void Flush()
    {
        if (_bufferLength > 0) FlushChunk(true);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing) Flush();
        _disposed = true;
        base.Dispose(disposing);
    }

    private void FlushChunk(bool isLast)
    {
        if (!isLast && _bufferLength != ChunkedStream.ChunkSize)
            throw new AgeCryptoException("stream: internal error: flush called with partial chunk");

        Logger.LogTrace("Flushing chunk, isLast: {IsLast}, bufferLength: {BufferLength}", isLast, _bufferLength);

        if (isLast) ChunkedStream.SetLastChunkFlag(_nonce);

        var plaintext = _buffer.AsSpan(0, _bufferLength).ToArray();

        var ciphertext = ChaCha20Poly1305.Encrypt(_key, _nonce, plaintext);

        _destination.Write(ciphertext, 0, ciphertext.Length);
        _bufferLength = 0;
        ChunkedStream.IncrementNonce(_nonce);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
///     Reader for chunked decryption, matching age implementation exactly.
/// </summary>
public class ChunkedStreamReader : Stream
{
    private static readonly ILogger<ChunkedStreamReader> Logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<ChunkedStreamReader>();

    private readonly byte[] _buffer;
    private readonly byte[] _key;
    private readonly byte[] _nonce;
    private readonly Stream _source;
    private bool _disposed;
    private Exception? _error;
    private byte[] _unread; // decrypted but unread data, backed by _buffer

    public ChunkedStreamReader(byte[] key, Stream source)
    {
        _key = key;
        _source = source;
        _buffer = new byte[ChunkedStream.EncChunkSize]; // Single buffer like age
        _nonce = new byte[12]; // All zeros initially
        _unread = Array.Empty<byte>();
        
        
        Logger.LogTrace("ChunkedStreamReader initialized with key: {KeyHex}", BitConverter.ToString(key));
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null) throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException();
        if (count == 0)
            return 0;

        Logger.LogTrace("Reading {Count} bytes from chunked stream", count);
        Logger.LogTrace("Output buffer size: {BufferSize}", buffer.Length);

        // If we have unread data, return it
        if (_unread.Length > 0)
        {
            var toRead = Math.Min(_unread.Length, count);
            Array.Copy(_unread, 0, buffer, offset, toRead);

            // Shift remaining data to the beginning
            if (toRead < _unread.Length)
            {
                var remaining = new byte[_unread.Length - toRead];
                Array.Copy(_unread, toRead, remaining, 0, remaining.Length);
                _unread = remaining;
                Logger.LogTrace("Remaining unread bytes: {RemainingLength}", remaining.Length);
            }
            else
            {
                _unread = Array.Empty<byte>();
                Logger.LogTrace("No remaining unread bytes");
            }

            return toRead;
        }

        if (_error != null)
        {
            // If the error is EndOfStreamException, return 0 (EOF), else throw
            if (_error is EndOfStreamException)
                return 0;
            throw new IOException("Error during chunked decryption", _error);
        }

        var isLast = ReadChunk();
        if (_error != null)
        {
            if (_error is EndOfStreamException)
                return 0;
            throw new IOException("Error during chunked decryption", _error);
        }

        var n = Math.Min(_unread.Length, count);
        Array.Copy(_unread, 0, buffer, offset, n);


        // Shift remaining data to the beginning
        if (n < _unread.Length)
        {
            var remaining = new byte[_unread.Length - n];
            Array.Copy(_unread, n, remaining, 0, remaining.Length);
            _unread = remaining;
        }
        else
        {
            _unread = Array.Empty<byte>();
            Logger.LogTrace("No remaining unread bytes after copy");
        }

        if (isLast)
        {
            Logger.LogTrace("Last chunk read, checking for trailing data");
            // Ensure there is an EOF after the last chunk as expected
            var trailingBuffer = new byte[1];
            var trailingRead = _source.Read(trailingBuffer, 0, 1);
            if (trailingRead > 0)
            {
                Logger.LogTrace("Found trailing data after last chunk: {TrailingDataHex}", BitConverter.ToString(trailingBuffer));
                _error = new AgeCryptoException("trailing data after end of encrypted file");
                throw new IOException("Error during chunked decryption", _error);
            }
            Logger.LogTrace("No trailing data found, EOF confirmed");
        }

        return n;
    }

    private bool ReadChunk()
    {
        if (_unread.Length != 0)
            throw new AgeCryptoException("stream: internal error: readChunk called with dirty buffer");


        // Read the encrypted chunk using ReadFull (matching age's io.ReadFull)
        var n = ReadFull(_source, _buffer, 0, _buffer.Length);

        var isLast = false;
        byte[] chunkData;

        if (n == 0)
        {
            // A message can't end without a marked chunk. This message is truncated.
            Logger.LogTrace("No data read, stream truncated");
            _error = new EndOfStreamException("Unexpected end of stream");
            return false;
        }

        if (n < _buffer.Length)
        {
            Logger.LogTrace("Short chunk read: {N} bytes (expected {ExpectedLength})", n, _buffer.Length);
            // The last chunk can be short, but not empty unless it's the first and only chunk
            if (!IsNonceZero() && n == 16) // 16 is ChaCha20-Poly1305 overhead
            {
                Logger.LogTrace("Last chunk is empty, this is an error");
                _error = new AgeCryptoException(
                    "last chunk is empty");
                return false;
            }

            chunkData = new byte[n];
            Array.Copy(_buffer, 0, chunkData, 0, n);
            isLast = true;
            
            SetLastChunkFlag(_nonce); // Always set last chunk flag on original nonce for short chunk
        }
        else
        {
            chunkData = _buffer;
            Logger.LogTrace("Full chunk read of {ChunkDataHex} bytes", chunkData.Length);
        }

        // Try to decrypt the chunk
        byte[] decrypted;
        try
        {
            decrypted = ChaCha20Poly1305.Decrypt(_key, _nonce, chunkData);
            Logger.LogTrace("Successfully decrypted chunk {DecryptedHex} bytes", decrypted.Length);
            
            // Only increment nonce after successful decryption (matching age implementation)
            IncNonce();
        }
        catch (CryptographicException ex) when (!isLast)
        {
            Logger.LogTrace("Decryption failed, retrying as last chunk: {Error}", ex.Message);
            // Check if this was a full-length final chunk (age retry logic)
            isLast = true;
            
            // Modify the original nonce in-place for the retry (matching Rust implementation)
            SetLastChunkFlag(_nonce);

            try
            {
                Logger.LogTrace("Retrying decryption with last chunk flag");
                decrypted = ChaCha20Poly1305.Decrypt(_key, _nonce, chunkData);
                Logger.LogTrace("Retry successful, decrypted: {DecryptedHex} bytes", decrypted.Length);
                
                // Only increment nonce after successful retry decryption
                IncNonce();
            }
            catch (CryptographicException ex2)
            {
                Logger.LogTrace("Retry also failed: {Error}", ex2.Message);
                _error = new CryptographicException(
                    $"failed to decrypt and authenticate payload chunk (retry): {ex2.Message}");
                return false;
            }
        }
        catch (CryptographicException ex)
        {
            Logger.LogTrace("Decryption failed: {Error}", ex.Message);
            _error = new CryptographicException($"failed to decrypt and authenticate payload chunk: {ex.Message}");
            return false;
        }

        _unread = decrypted;

        return isLast;
    }

    // Helper to read exactly 'count' bytes from the stream, returns number of bytes read
    private static int ReadFull(Stream stream, byte[] buffer, int offset, int count)
    {
        var totalRead = 0;
        
        while (totalRead < count)
        {
            var bytesRead = stream.Read(buffer, offset + totalRead, count - totalRead);
            if (bytesRead == 0)
                break;
            totalRead += bytesRead;
        }

        return totalRead;
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
        }

        _disposed = true;
        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    private void IncNonce()
    {
        ChunkedStream.IncrementNonce(_nonce);
    }

    private void SetLastChunkFlag(byte[] nonce)
    {
        ChunkedStream.SetLastChunkFlag(nonce);
    }

    private bool IsNonceZero()
    {
        var isZero = ChunkedStream.IsNonceZero(_nonce);
        return isZero;
    }
}