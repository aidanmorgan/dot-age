using System;
using System.Text;
using System.Collections.Generic;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Utils;

/// <summary>
///     Bech32 encoding and decoding implementation.
///     Based on the Go implementation from the age project.
/// </summary>
public static class Bech32
{
    private static readonly ILogger _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(Bech32));

    private static readonly string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static readonly uint[] Generator = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

    /// <summary>
    ///     Encodes data to Bech32 format.
    /// </summary>
    /// <param name="hrp">The human-readable part.</param>
    /// <param name="data">The data to encode.</param>
    /// <returns>The Bech32 encoded string.</returns>
    public static string Encode(string hrp, byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (string.IsNullOrEmpty(hrp)) throw new AgeFormatException("HRP cannot be null or empty");

        _logger.LogTrace("Encoding Bech32 - HRP: {Hrp}, Data length: {DataLength}", hrp, data.Length);

        // Convert 8-bit data to 5-bit
        var values = ConvertBits(data, 8, 5, true);
        if (values == null) throw new AgeFormatException("Invalid data for encoding");

        // Validate HRP
        foreach (var c in hrp)
        {
            if (c < 33 || c > 126)
                throw new AgeFormatException($"Invalid HRP character: {c}");
        }

        var isLower = hrp.ToLowerInvariant() == hrp;
        var lowerHrp = hrp.ToLowerInvariant();

        var ret = new StringBuilder();
        ret.Append(lowerHrp);
        ret.Append('1');

        // Add data part
        foreach (var p in values)
        {
            ret.Append(Charset[p]);
        }

        // Add checksum
        var checksum = CreateChecksum(lowerHrp, values);
        _logger.LogTrace("Generated checksum: {ChecksumHex}", BitConverter.ToString(checksum));

        foreach (var p in checksum)
        {
            ret.Append(Charset[p]);
        }

        var result = isLower ? ret.ToString() : ret.ToString().ToUpperInvariant();

        return result;
    }

    /// <summary>
    ///     Decodes a Bech32 string.
    /// </summary>
    /// <param name="s">The Bech32 string to decode.</param>
    /// <returns>A tuple containing the HRP and decoded data.</returns>
    public static (string hrp, byte[] data) Decode(string s)
    {
        if (string.IsNullOrEmpty(s)) throw new AgeFormatException("String cannot be null or empty");

        // Check for mixed case
        if (s.ToLowerInvariant() != s && s.ToUpperInvariant() != s)
        {
            _logger.LogTrace("Mixed case not allowed in Bech32 string");
            throw new AgeFormatException("Mixed case not allowed");
        }

        var pos = s.LastIndexOf('1');
        if (pos < 1 || pos + 7 > s.Length)
        {
            _logger.LogTrace("Separator '1' at invalid position: {Position}", pos);
            throw new AgeFormatException("Separator '1' at invalid position");
        }

        var hrp = s.Substring(0, pos);
        _logger.LogTrace("Extracted HRP: {Hrp}", hrp);

        // Validate HRP characters
        foreach (var c in hrp)
        {
            if (c < 33 || c > 126)
                throw new AgeFormatException($"Invalid character in human-readable part: {c}");
        }

        var lowerS = s.ToLowerInvariant();
        var data = new List<byte>();

        // Decode data part
        for (var i = pos + 1; i < lowerS.Length; i++)
        {
            var d = Charset.IndexOf(lowerS[i]);
            if (d == -1)
            {
                _logger.LogTrace("Invalid character in data part: {Char}", lowerS[i]);
                throw new AgeFormatException($"Invalid character in data part: {lowerS[i]}");
            }
            data.Add((byte)d);
        }

        // Verify checksum
        if (!VerifyChecksum(hrp, data.ToArray()))
        {
            _logger.LogTrace("Invalid checksum in Bech32 string");
            throw new AgeFormatException("Invalid checksum");
        }

        // Convert 5-bit data back to 8-bit, only for the data part (excluding the 6 checksum bytes)
        var result = ConvertBits(data.ToArray(), 5, 8, false, data.Count - 6);
        if (result == null)
        {
            _logger.LogTrace("Invalid data conversion from 5-bit to 8-bit");
            throw new AgeFormatException("Invalid data conversion");
        }

        return (hrp, result);
    }

    private static uint Polymod(byte[] values)
    {
        _logger.LogTrace("Computing polymod for {ValueCount}", values.Length);

        var chk = 1u;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5;
            chk = chk ^ v;
            for (var i = 0; i < 5; i++)
            {
                var bit = (top >> i) & 1;
                if (bit == 1)
                {
                    chk ^= Generator[i];
                }
            }
        }

        _logger.LogTrace("Polymod result: {PolymodResult:X8}", chk);
        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        _logger.LogTrace("Expanding HRP: {Hrp}", hrp);

        var h = hrp.ToLowerInvariant();
        var ret = new List<byte>();

        foreach (var c in h)
        {
            ret.Add((byte)(c >> 5));
        }
        ret.Add(0);

        foreach (var c in h)
        {
            ret.Add((byte)(c & 31));
        }

        _logger.LogTrace("Expanded HRP: {ExpandedHrpHex}", BitConverter.ToString(ret.ToArray()));
        return ret.ToArray();
    }

    private static bool VerifyChecksum(string hrp, byte[] data)
    {
        _logger.LogTrace("Verifying checksum - HRP: {Hrp}, Data: {DataHex}", hrp, BitConverter.ToString(data));

        var values = new List<byte>();
        values.AddRange(HrpExpand(hrp));
        values.AddRange(data);

        var polymod = Polymod(values.ToArray());
        var isValid = polymod == 1;

        _logger.LogTrace("Checksum verification result: {IsValid} (polymod: {Polymod:X8})", isValid, polymod);
        return isValid;
    }

    private static byte[] CreateChecksum(string hrp, byte[] data)
    {
        var values = new List<byte>();
        values.AddRange(HrpExpand(hrp));
        values.AddRange(data);
        values.AddRange(new byte[] { 0, 0, 0, 0, 0, 0 });

        var mod = Polymod(values.ToArray()) ^ 1;
        var ret = new byte[6];

        for (var p = 0; p < ret.Length; p++)
        {
            var shift = 5 * (5 - p);
            ret[p] = (byte)((mod >> shift) & 31);
        }

        _logger.LogTrace("Created checksum: {ChecksumHex}", BitConverter.ToString(ret));
        return ret;
    }

    private static byte[]? ConvertBits(byte[] data, byte fromBits, byte toBits, bool pad, int? length = null)
    {
        var ret = new List<byte>();
        var acc = 0u;
        var bits = 0;
        var maxv = (byte)((1 << toBits) - 1);
        int dataLen = length ?? data.Length;

        for (var idx = 0; idx < dataLen; idx++)
        {
            var value = data[idx];
            if ((value >> fromBits) != 0)
            {
                _logger.LogTrace("Invalid data range at index {Index}: {Value}", idx, value);
                return null; // Invalid data range
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                ret.Add((byte)((acc >> bits) & maxv));
            }
        }

        if (pad)
        {
            if (bits > 0)
            {
                ret.Add((byte)((acc << (toBits - bits)) & maxv));
            }
        }
        else if (bits >= fromBits)
        {
            _logger.LogTrace("Invalid padding - bits: {Bits}, fromBits: {FromBits}", bits, fromBits);
            return null;
        }

        return ret.ToArray();
    }
} 