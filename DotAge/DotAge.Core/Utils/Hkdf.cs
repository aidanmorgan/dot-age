using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Core.Utils;

/// <summary>
///     HKDF implementation for key derivation.
/// </summary>
public static class Hkdf
{
    private static readonly Lazy<ILogger> _logger = new(() => LoggerFactory.CreateLogger(nameof(Hkdf)));

    /// <summary>
    ///     Derives a key using HKDF (HMAC-based Key Derivation Function).
    ///     This matches the Go implementation's hkdf.New usage.
    /// </summary>
    /// <param name="ikm">Input Keying Material (secret).</param>
    /// <param name="salt">Salt value.</param>
    /// <param name="info">Info string.</param>
    /// <param name="length">Length of the derived key.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(byte[] ikm, byte[] salt, string info, int length)
    {
        if (ikm == null) throw new ArgumentNullException(nameof(ikm));
        if (salt == null) throw new ArgumentNullException(nameof(salt));
        if (string.IsNullOrEmpty(info)) throw new ArgumentException("Info cannot be null or empty", nameof(info));
        if (length <= 0) throw new ArgumentException("Length must be positive", nameof(length));

        _logger.Value.LogTrace("Starting HKDF key derivation");
        _logger.Value.LogTrace("IKM length: {IkmLength} bytes", ikm.Length);
        _logger.Value.LogTrace("Salt length: {SaltLength} bytes", salt.Length);
        _logger.Value.LogTrace("Info: '{Info}' (length: {InfoLength})", info, info.Length);
        _logger.Value.LogTrace("Length: {Length}", length);
        _logger.Value.LogTrace("IKM: {Ikm}", BitConverter.ToString(ikm));
        _logger.Value.LogTrace("Salt: {Salt}", BitConverter.ToString(salt));

        // Extract PRK (RFC 5869, Go/rust reference: HMAC-SHA256(salt, IKM))
        byte[] prk;
        using (var hmac = new HMACSHA256(salt))
        {
            prk = hmac.ComputeHash(ikm);
        }

        _logger.Value.LogTrace("PRK (Pseudo-Random Key) length: {PrkLength} bytes", prk.Length);
        _logger.Value.LogTrace("PRK: {Prk}", BitConverter.ToString(prk));

        // Expand
        var infoBytes = Encoding.UTF8.GetBytes(info);
        _logger.Value.LogTrace("Info bytes length: {InfoBytesLength} bytes", infoBytes.Length);
        _logger.Value.LogTrace("Info bytes: {InfoBytes}", BitConverter.ToString(infoBytes));

        var okm = Expand(prk, infoBytes, length);
        _logger.Value.LogTrace("HKDF derivation complete. Result length: {ResultLength} bytes", okm.Length);
        _logger.Value.LogTrace("OKM: {Okm}", BitConverter.ToString(okm));

        return okm;
    }

    /// <summary>
    ///     HKDF-Expand step (RFC 5869), matching Go/rust reference implementations.
    ///     See: https://github.com/FiloSottile/age/blob/main/internal/stream/stream.go and
    ///     https://github.com/str4d/rage/blob/master/age-core/src/primitives.rs
    /// </summary>
    private static byte[] Expand(byte[] prk, byte[] info, int length)
    {
        // RFC 5869: N = ceil(length / HashLen)
        var hashLen = 32; // SHA-256 output size
        var n = (int)Math.Ceiling((double)length / hashLen);
        if (n > 255) throw new ArgumentException("Cannot expand to more than 255 blocks of hash length");
        var okm = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        using var hmac = new HMACSHA256(prk);
        for (var i = 1; i <= n; i++)
        {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            var input = new byte[previous.Length + info.Length + 1];
            Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
            Buffer.BlockCopy(info, 0, input, previous.Length, info.Length);
            input[input.Length - 1] = (byte)i;
            previous = hmac.ComputeHash(input);
            var toCopy = Math.Min(hashLen, length - offset);
            Buffer.BlockCopy(previous, 0, okm, offset, toCopy);
            offset += toCopy;
        }

        return okm;
    }
}