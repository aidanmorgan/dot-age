using System.Security.Cryptography;
using System.Text;

namespace DotAge.Core.Utils;

/// <summary>
///     HKDF implementation for key derivation.
/// </summary>
public static class Hkdf
{
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
        // Use empty salt (not 32 bytes of zeros) when salt is empty, matching Go HKDF behavior
        using var hmac = new HMACSHA256(salt);
        var prk = hmac.ComputeHash(ikm);

        var infoBytes = Encoding.ASCII.GetBytes(info);
        var result = new byte[length];
        var t = new byte[0];
        var offset = 0;

        for (var i = 1; offset < length; i++)
        {
            using var hmacExpand = new HMACSHA256(prk);
            if (t.Length > 0) hmacExpand.TransformBlock(t, 0, t.Length, null, 0);
            hmacExpand.TransformBlock(infoBytes, 0, infoBytes.Length, null, 0);
            hmacExpand.TransformFinalBlock(new[] { (byte)i }, 0, 1);
            t = hmacExpand.Hash ?? new byte[0];

            var copyLength = Math.Min(t.Length, length - offset);
            Array.Copy(t, 0, result, offset, copyLength);
            offset += copyLength;
        }

        return result;
    }
}