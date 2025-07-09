using System.Security.Cryptography;
using System.Text;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Utils;

/// <summary>
///     HKDF implementation for key derivation.
/// </summary>
public static class Hkdf
{
    private static readonly ILogger _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(Hkdf));

    /// <summary>
    ///     Derives a key using HKDF (HMAC-based Key Derivation Function).
    /// </summary>
    /// <param name="ikm">Input Keying Material.</param>
    /// <param name="salt">Salt value.</param>
    /// <param name="info">Info string.</param>
    /// <param name="length">Length of the derived key.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(byte[] ikm, byte[] salt, string info, int length)
    {
        _logger.LogTrace("Starting HKDF key derivation");
        _logger.LogTrace("IKM: {IkmHex}", BitConverter.ToString(ikm));
        _logger.LogTrace("Salt: {SaltHex}", BitConverter.ToString(salt));
        _logger.LogTrace("Info: {Info}", info);
        _logger.LogTrace("Length: {Length}", length);

        // Use empty salt (not 32 bytes of zeros) when salt is empty, matching Go HKDF behavior
        using var hmac = new HMACSHA256(salt);
        var prk = hmac.ComputeHash(ikm);
        _logger.LogTrace("PRK (Pseudo-Random Key): {PrkHex}", BitConverter.ToString(prk));

        var infoBytes = Encoding.ASCII.GetBytes(info);
        _logger.LogTrace("Info bytes: {InfoBytesHex}", BitConverter.ToString(infoBytes));

        var result = new byte[length];
        var t = Array.Empty<byte>();
        var offset = 0;

        for (var i = 1; offset < length; i++)
        {
            using var hmacExpand = new HMACSHA256(prk);
            if (t.Length > 0) 
            {
                hmacExpand.TransformBlock(t, 0, t.Length, null, 0);
            }
            
            hmacExpand.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            hmacExpand.TransformFinalBlock(new[] { (byte)i }, 0, 1);
            t = hmacExpand.Hash ?? new byte[0];

            var copyLength = Math.Min(t.Length, length - offset);
            Array.Copy(t, 0, result, offset, copyLength);
            offset += copyLength;

        }

        _logger.LogTrace("HKDF derivation complete. Result: {ResultHex}", BitConverter.ToString(result));
        return result;
    }
}