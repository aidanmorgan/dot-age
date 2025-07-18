using DotAge.Core.Crypto;

namespace DotAge.Tests;

/// <summary>
///     Tests for streaming I/O operations including ChunkedStream functionality.
/// </summary>
public class StreamingTests
{
    [Fact]
    public void TestExactChunkSizeEncryptionDecryption()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);

        var testData = new byte[65536];
        new Random(123).NextBytes(testData);

        // Encrypt the data
        byte[] encryptedData;
        using (var ms = new MemoryStream())
        {
            using (var writer = ChunkedStream.CreateWriter(key, ms))
            {
                writer.Write(testData, 0, testData.Length);
            }

            encryptedData = ms.ToArray();
        }

        // Decrypt the data
        byte[] decryptedData;
        using (var ms = new MemoryStream(encryptedData))
        {
            using (var reader = ChunkedStream.CreateReader(key, ms))
            {
                decryptedData = new byte[testData.Length];
                var bytesRead = reader.Read(decryptedData, 0, decryptedData.Length);


                Assert.Equal(testData.Length, bytesRead);
                Assert.Equal(testData, decryptedData);
            }
        }
    }

    [Fact]
    public void TestMultipleExactChunks()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);

        var testData = new byte[131072]; // Exactly 2 * 64KB
        new Random(123).NextBytes(testData);

        // Encrypt the data
        byte[] encryptedData;
        using (var ms = new MemoryStream())
        {
            using (var writer = ChunkedStream.CreateWriter(key, ms))
            {
                writer.Write(testData, 0, testData.Length);
            }

            encryptedData = ms.ToArray();
        }

        // Decrypt the data
        byte[] decryptedData;
        using (var ms = new MemoryStream(encryptedData))
        {
            using (var reader = ChunkedStream.CreateReader(key, ms))
            {
                decryptedData = new byte[testData.Length];
                var bytesRead = reader.Read(decryptedData, 0, decryptedData.Length);

                Assert.Equal(testData.Length, bytesRead);
                Assert.Equal(testData, decryptedData);
            }
        }
    }

    [Fact]
    public void TestChunkSizeMinusOne()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);

        var testData = new byte[65535]; // 64KB - 1
        new Random(123).NextBytes(testData);

        // Encrypt the data
        byte[] encryptedData;
        using (var ms = new MemoryStream())
        {
            using (var writer = ChunkedStream.CreateWriter(key, ms))
            {
                writer.Write(testData, 0, testData.Length);
            }

            encryptedData = ms.ToArray();
        }

        // Decrypt the data
        byte[] decryptedData;
        using (var ms = new MemoryStream(encryptedData))
        {
            using (var reader = ChunkedStream.CreateReader(key, ms))
            {
                decryptedData = new byte[testData.Length];
                var bytesRead = reader.Read(decryptedData, 0, decryptedData.Length);

                Assert.Equal(testData.Length, bytesRead);
                Assert.Equal(testData, decryptedData);
            }
        }
    }

    [Fact]
    public void TestChunkSizePlusOne()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);

        var testData = new byte[65537]; // 64KB + 1
        new Random(123).NextBytes(testData);

        // Encrypt the data
        byte[] encryptedData;
        using (var ms = new MemoryStream())
        {
            using (var writer = ChunkedStream.CreateWriter(key, ms))
            {
                writer.Write(testData, 0, testData.Length);
            }

            encryptedData = ms.ToArray();
        }

        // Decrypt the data
        byte[] decryptedData;
        using (var ms = new MemoryStream(encryptedData))
        {
            using (var reader = ChunkedStream.CreateReader(key, ms))
            {
                decryptedData = new byte[testData.Length];
                var bytesRead = reader.Read(decryptedData, 0, decryptedData.Length);

                Assert.Equal(testData.Length, bytesRead);
                Assert.Equal(testData, decryptedData);
            }
        }
    }

    [Fact]
    public void TestStressExactChunkSize()
    {
        var key = new byte[32];
        new Random(42).NextBytes(key);

        for (var i = 0; i < 100; i++)
        {
            var testData = new byte[65536];
            new Random(i).NextBytes(testData);

            // Encrypt the data
            byte[] encryptedData;
            using (var ms = new MemoryStream())
            {
                using (var writer = ChunkedStream.CreateWriter(key, ms))
                {
                    writer.Write(testData, 0, testData.Length);
                }

                encryptedData = ms.ToArray();
            }

            // Decrypt the data
            byte[] decryptedData;
            using (var ms = new MemoryStream(encryptedData))
            {
                using (var reader = ChunkedStream.CreateReader(key, ms))
                {
                    decryptedData = new byte[testData.Length];
                    var bytesRead = reader.Read(decryptedData, 0, decryptedData.Length);

                    Assert.Equal(testData.Length, bytesRead);
                    Assert.Equal(testData, decryptedData);
                }
            }
        }
    }
}