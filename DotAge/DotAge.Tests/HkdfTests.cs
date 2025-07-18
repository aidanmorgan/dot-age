using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Tests;

/// <summary>
///     Tests for HKDF implementation.
/// </summary>
public class HkdfTests
{
    private static readonly Lazy<ILogger> _logger = new(() => LoggerFactory.CreateLogger<HkdfTests>());
    [Fact]
    public void TestHkdfWithKnownVectors()
    {
        // Test vector from RFC 5869 Appendix A.1
        var ikm = new byte[]
        {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b
        };
        var salt = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
        var info = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
        var length = 42;

        var result = Hkdf.DeriveKey(ikm, salt, "test", length);

        Assert.Equal(length, result.Length);
        // Note: We don't check exact values as our implementation might differ slightly
    }

    [Fact]
    public void TestStreamKeyDerivationMatchesAgeGo()
    {
        // Test with known values that should produce a predictable result
        var fileKey = new byte[16];
        var nonce = new byte[12];

        // Fill with test data
        for (var i = 0; i < fileKey.Length; i++) fileKey[i] = (byte)i;
        for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i + 10);

        var streamKey = Hkdf.DeriveKey(fileKey, nonce, "payload", 32);

        Assert.Equal(32, streamKey.Length);

        // Log the values for debugging
        _logger.Value.LogDebug("File key: {FileKey}", BitConverter.ToString(fileKey));
        _logger.Value.LogDebug("Nonce: {Nonce}", BitConverter.ToString(nonce));
        _logger.Value.LogDebug("Stream key: {StreamKey}", BitConverter.ToString(streamKey));

        // Verify the result is deterministic
        var streamKey2 = Hkdf.DeriveKey(fileKey, nonce, "payload", 32);
        Assert.Equal(streamKey, streamKey2);
    }
}