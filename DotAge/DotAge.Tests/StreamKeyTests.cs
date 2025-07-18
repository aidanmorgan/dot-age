using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Tests;

/// <summary>
///     Tests for stream key derivation.
/// </summary>
public class StreamKeyTests
{
    private static readonly Lazy<ILogger> _logger = new(() => LoggerFactory.CreateLogger<StreamKeyTests>());
    [Fact]
    public void TestStreamKeyDerivation()
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

    [Fact]
    public void TestStreamKeyWithZeroNonce()
    {
        // Test with zero nonce (as per age spec)
        var fileKey = new byte[16];
        var nonce = new byte[12]; // All zeros

        // Fill file key with test data
        for (var i = 0; i < fileKey.Length; i++) fileKey[i] = (byte)i;

        var streamKey = Hkdf.DeriveKey(fileKey, nonce, "payload", 32);

        Assert.Equal(32, streamKey.Length);
        _logger.Value.LogDebug("File key: {FileKey}", BitConverter.ToString(fileKey));
        _logger.Value.LogDebug("Nonce (zeros): {Nonce}", BitConverter.ToString(nonce));
        _logger.Value.LogDebug("Stream key: {StreamKey}", BitConverter.ToString(streamKey));
    }
}