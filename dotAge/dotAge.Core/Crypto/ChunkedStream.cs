using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Crypto;

/// <summary>
///     Provides chunked encryption and decryption for age files.
///     Implements the age file format specification.
/// </summary>
public static class ChunkedStream
{
    /// <summary>
    ///     The size of each chunk in bytes (64KB).
    /// </summary>
    public const int ChunkSize = 65536;

    private static readonly Lazy<ILogger> Logger = new(() => LoggerFactory.CreateLogger(nameof(ChunkedStream)));

    /// <summary>
    ///     Creates a ChunkedStreamWriter for encrypting data in chunks.
    /// </summary>
    /// <param name="key">The encryption key.</param>
    /// <param name="output">The output stream.</param>
    /// <returns>A ChunkedStreamWriter instance.</returns>
    public static ChunkedStreamWriter CreateWriter(byte[] key, Stream output)
    {
        return new ChunkedStreamWriter(key, output);
    }

    /// <summary>
    ///     Creates a ChunkedStreamReader for decrypting data in chunks.
    /// </summary>
    /// <param name="key">The decryption key.</param>
    /// <param name="input">The input stream.</param>
    /// <returns>A ChunkedStreamReader instance.</returns>
    public static ChunkedStreamReader CreateReader(byte[] key, Stream input)
    {
        return new ChunkedStreamReader(key, input);
    }

    /// <summary>
    ///     Increments a 12-byte nonce in little-endian format.
    ///     Following age spec: increment the first 11 bytes (88-bit counter), leave byte 11 for last chunk flag.
    ///     Reference: https://github.com/FiloSottile/age/blob/main/internal/stream/stream.go#L109 and
    ///     https://github.com/str4d/rage/blob/master/age-core/src/stream.rs
    /// </summary>
    /// <param name="nonce">The nonce to increment (modified in place).</param>
    private static void IncrementNonce(byte[] nonce)
    {
        // Increment the first 11 bytes (88-bit counter) as per age spec
        // Go implementation: for i := len(nonce) - 2; i >= 0; i--
        for (var i = nonce.Length - 2; i >= 0; i--)
        {
            nonce[i]++;
            if (nonce[i] != 0)
                break;
            if (i == 0)
                // The counter is 88 bits, this is unreachable in practice
                throw new InvalidOperationException("Chunk counter wrapped around");
        }
    }

    /// <summary>
    ///     Sets the last chunk flag in a nonce.
    ///     Reference: https://github.com/FiloSottile/age/blob/main/internal/stream/stream.go#L123
    /// </summary>
    /// <param name="nonce">The nonce to modify (modified in place).</param>
    private static void SetLastChunkFlag(byte[] nonce)
    {
        nonce[11] = 0x01; // Set last chunk flag as per age spec
    }

    /// <summary>
    ///     Checks if a nonce is all zeros.
    /// </summary>
    /// <param name="nonce">The nonce to check.</param>
    /// <returns>True if the nonce is all zeros.</returns>
    private static bool IsNonceZero(byte[] nonce)
    {
        for (var i = 0; i < nonce.Length; i++)
            if (nonce[i] != 0)
                return false;
        return true;
    }

    /// <summary>
    ///     ChunkedStreamWriter for encrypting data in chunks.
    /// </summary>
    public class ChunkedStreamWriter : Stream
    {
        private readonly byte[] _buffer = new byte[ChunkSize];
        private readonly byte[] _key;
        private readonly byte[] _nonce;
        private readonly Stream _output;
        private int _bufferLength;
        private bool _closed;
        private bool _disposed;

        public ChunkedStreamWriter(byte[] key, Stream output)
        {
            _key = (byte[])key.Clone();
            _output = output ?? throw new ArgumentNullException(nameof(output));
            _buffer = new byte[ChunkSize];
            _nonce = new byte[12];
            _bufferLength = 0;
            _disposed = false;
            _closed = false;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ChunkedStreamWriter));
            if (_closed) throw new InvalidOperationException("Writer is closed");

            var remaining = count;
            var bufferOffset = offset;

            while (remaining > 0)
            {
                var toWrite = Math.Min(remaining, ChunkSize - _bufferLength);
                Buffer.BlockCopy(buffer, bufferOffset, _buffer, _bufferLength, toWrite);
                _bufferLength += toWrite;
                remaining -= toWrite;
                bufferOffset += toWrite;

                if (_bufferLength == ChunkSize && remaining > 0) FlushChunk(false);
            }
        }

        public override void Flush()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ChunkedStreamWriter));
            if (_closed) return;

            if (_bufferLength > 0)
                FlushChunk(true);
            else
                FlushChunk(true);
            _closed = true;
        }

        private void FlushChunk(bool isLast)
        {
            if (!isLast && _bufferLength != ChunkSize)
                throw new InvalidOperationException("Internal error: flush called with partial chunk");

            var chunkData = new byte[_bufferLength];
            Buffer.BlockCopy(_buffer, 0, chunkData, 0, _bufferLength);
            var nonceCopy = (byte[])_nonce.Clone();

            if (isLast) SetLastChunkFlag(nonceCopy);

            var encrypted = ChaCha20Poly1305.Encrypt(_key, nonceCopy, chunkData);
            _output.Write(encrypted, 0, encrypted.Length);
            IncrementNonce(_nonce);
            _bufferLength = 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                Flush();
                _output?.Dispose();
            }

            _disposed = true;
            base.Dispose(disposing);
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

    public class ChunkedStreamReader : Stream
    {
        private readonly byte[] _buffer;
        private readonly Stream _input;
        private readonly byte[] _key;
        private readonly byte[] _nonce;
        private readonly byte[] _unread;
        private bool _disposed;
        private bool _eof;
        private bool _isLastChunk;
        private bool _trailingDataChecked;
        private int _unreadLength;

        public ChunkedStreamReader(byte[] key, Stream input)
        {
            _key = (byte[])key.Clone();
            _input = input ?? throw new ArgumentNullException(nameof(input));
            _buffer = new byte[ChunkSize + 16];
            _nonce = new byte[12];
            _unread = new byte[ChunkSize];
            _unreadLength = 0;
            _disposed = false;
            _isLastChunk = false;
            _eof = false;
            _trailingDataChecked = false;
        }

        public override bool CanRead => true;
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
            if (_disposed) throw new ObjectDisposedException(nameof(ChunkedStreamReader));
            if (_eof && _unreadLength == 0) return 0;
            var totalRead = 0;
            if (_unreadLength > 0)
            {
                var toRead = Math.Min(count, _unreadLength);
                Buffer.BlockCopy(_unread, 0, buffer, offset, toRead);
                Buffer.BlockCopy(_unread, toRead, _unread, 0, _unreadLength - toRead);
                _unreadLength -= toRead;
                totalRead += toRead;
                offset += toRead;
                count -= toRead;
            }

            while (count > 0 && !_eof)
            {
                var chunkData = ReadChunkInternal();
                if (chunkData == null) break;
                var toRead = Math.Min(count, chunkData.Length);
                Buffer.BlockCopy(chunkData, 0, buffer, offset, toRead);
                totalRead += toRead;
                offset += toRead;
                count -= toRead;
                if (toRead < chunkData.Length)
                {
                    var remaining = chunkData.Length - toRead;
                    Buffer.BlockCopy(chunkData, toRead, _unread, 0, remaining);
                    _unreadLength = remaining;
                }
            }

            return totalRead;
        }

        private byte[]? ReadChunkInternal()
        {
            if (_isLastChunk)
            {
                if (!_trailingDataChecked)
                {
                    _trailingDataChecked = true;
                    if (_input.ReadByte() != -1) throw new AgeFormatException("Trailing data after last chunk");
                }

                _eof = true;
                return null;
            }

            var encryptedSize = ChunkSize + 16;
            var n = 0;
            while (n < encryptedSize)
            {
                var read = _input.Read(_buffer, n, encryptedSize - n);
                if (read == 0)
                {
                    if (n == 0)
                    {
                        _eof = true;
                        return null;
                    }

                    break;
                }

                n += read;
            }

            // Determine if this is the last chunk based on read size (matching Go implementation)
            var isLast = n < encryptedSize;
            if (isLast)
            {
                // Check for empty last chunk (only 16 bytes = just the auth tag)
                if (!IsNonceZero(_nonce) && n == 16) throw new AgeFormatException("last chunk is empty");
                // Set the last chunk flag immediately (matching Go implementation)
                SetLastChunkFlag(_nonce);
            }
            else
            {
                // If we read exactly a full chunk, we need to check if there's more data
                // Try to read one more byte to see if this is actually the last chunk
                var nextByte = _input.ReadByte();
                if (nextByte == -1)
                {
                    // No more data, this was the last chunk
                    isLast = true;
                    SetLastChunkFlag(_nonce);
                }
                else
                {
                    // Put the byte back for the next read
                    _input.Position = _input.Position - 1;
                }
            }

            var chunkData = new byte[n];
            Buffer.BlockCopy(_buffer, 0, chunkData, 0, n);

            // First try with the current nonce (matching Go implementation)
            byte[] decrypted;
            try
            {
                decrypted = ChaCha20Poly1305.Decrypt(_key, _nonce, chunkData);
            }
            catch (AgeCryptoException)
            {
                // If decryption failed and this is not already marked as last, try with last chunk flag
                if (!isLast)
                {
                    // Try again with the last chunk flag
                    SetLastChunkFlag(_nonce);
                    decrypted = ChaCha20Poly1305.Decrypt(_key, _nonce, chunkData);
                    isLast = true;
                }
                else
                {
                    throw;
                }
            }

            IncrementNonce(_nonce);
            if (isLast) _isLastChunk = true;
            return decrypted;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed && disposing) _input?.Dispose();
            _disposed = true;
            base.Dispose(disposing);
        }

        public override void Flush()
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

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}