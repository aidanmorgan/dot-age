using System.Text;
using DotAge.Core.Exceptions;
using DotAge.Core.Utils;

namespace DotAge.Tests;

/// <summary>
///     Tests for encoding and decoding utilities including Base64 and Bech32.
/// </summary>
public class EncodingTests
{
    [Fact]
    public void Base64Utils_EncodingDecoding_Works()
    {
        var data = Encoding.UTF8.GetBytes("Hello, World!");
        var encoded = Base64Utils.EncodeToString(data);
        var decoded = Base64Utils.DecodeString(encoded);

        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Base64Utils_UnpaddedBase64_Works()
    {
        // Test data that represents a 32-byte X25519 public key
        var testData = new byte[32];
        for (var i = 0; i < 32; i++) testData[i] = (byte)i;

        // Encode using unpadded base64 (like age does)
        var encoded = Convert.ToBase64String(testData).Replace("=", "");

        // Decode using our method (should add padding back)
        var decoded = Base64Utils.DecodeString(encoded);

        Assert.Equal(32, decoded.Length);
        Assert.Equal(testData, decoded);
    }

    [Fact]
    public void Base64Utils_WithPadding_Works()
    {
        // Test data that represents a 32-byte X25519 public key
        var testData = new byte[32];
        for (var i = 0; i < 32; i++) testData[i] = (byte)i;

        // Encode using standard base64 with padding
        var encoded = Convert.ToBase64String(testData);

        // Decode using our method
        var decoded = Base64Utils.DecodeString(encoded);

        Assert.Equal(32, decoded.Length);
        Assert.Equal(testData, decoded);
    }

    [Fact]
    public void Base64Utils_EdgeCases_Work()
    {
        // Test various lengths that might cause padding issues
        var testCases = new[]
        {
            new byte[1] { 0x01 },
            new byte[2] { 0x01, 0x02 },
            new byte[3] { 0x01, 0x02, 0x03 },
            new byte[30]
            {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
            },
            new byte[31]
            {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            },
            new byte[]
            {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            }
        };

        foreach (var testData in testCases)
        {
            // Test both padded and unpadded
            var paddedEncoded = Convert.ToBase64String(testData);
            var unpaddedEncoded = paddedEncoded.Replace("=", "");

            var paddedDecoded = Base64Utils.DecodeString(paddedEncoded);
            var unpaddedDecoded = Base64Utils.DecodeString(unpaddedEncoded);

            Assert.Equal(testData.Length, paddedDecoded.Length);
            Assert.Equal(testData.Length, unpaddedDecoded.Length);
            Assert.Equal(testData, paddedDecoded);
            Assert.Equal(testData, unpaddedDecoded);
        }
    }

    [Fact]
    public void Base64Utils_InvalidInput_ThrowsException()
    {
        // Test invalid base64 strings
        Assert.Throws<AgeFormatException>(() => Base64Utils.DecodeString("invalid!"));
        Assert.Throws<AgeFormatException>(() => Base64Utils.DecodeString("a\nb"));
        // Empty string is actually valid base64 (decodes to 0 bytes)
        var emptyResult = Base64Utils.DecodeString("");
        Assert.Empty(emptyResult);
    }

    [Fact]
    public void Base64_RFC4648_TestVectors()
    {
        // RFC 4648 test vectors for Base64 encoding/decoding
        var cases = new[]
        {
            (input: "", encoded: ""),
            (input: "f", encoded: "Zg"),
            (input: "fo", encoded: "Zm8"),
            (input: "foo", encoded: "Zm9v"),
            (input: "foob", encoded: "Zm9vYg"),
            (input: "fooba", encoded: "Zm9vYmE"),
            (input: "foobar", encoded: "Zm9vYmFy")
        };
        foreach (var (input, encoded) in cases)
        {
            var bytes = Encoding.ASCII.GetBytes(input);
            var enc = Base64Utils.EncodeToString(bytes);
            Assert.Equal(encoded, enc);
            var dec = Base64Utils.DecodeString(encoded);
            Assert.Equal(bytes, dec);
        }
    }

    [Fact]
    public void Bech32_EncodingDecoding_Works()
    {
        var data = Encoding.UTF8.GetBytes("test data");
        var encoded = Bech32.Encode("age", data);
        var (hrp, decoded) = Bech32.Decode(encoded);

        Assert.Equal("age", hrp);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Bech32_InvalidInput_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Bech32.Decode("invalid"));
        Assert.Throws<AgeFormatException>(() => Bech32.Decode(""));
    }
}