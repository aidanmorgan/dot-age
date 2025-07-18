using System.Diagnostics;

namespace DotAge.Tests;

/// <summary>
///     Utility methods for unit tests.
/// </summary>
public static class TestUtils
{
    /// <summary>
    ///     Creates a temporary directory for testing.
    /// </summary>
    /// <param name="prefix">Prefix for the directory name.</param>
    /// <returns>The path to the created temporary directory.</returns>
    public static string CreateTempDirectory(string prefix)
    {
        var tempPath = Path.GetTempPath();
        var dirName = $"{prefix}-{Guid.NewGuid():N}";
        var fullPath = Path.Combine(tempPath, dirName);
        Directory.CreateDirectory(fullPath);
        return fullPath;
    }

    /// <summary>
    ///     Safely deletes a directory, ignoring errors.
    /// </summary>
    /// <param name="path">The path to the directory to delete.</param>
    public static void SafeDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, true);
        }
        catch (Exception)
        {
            // Ignore errors during cleanup
        }
    }

    /// <summary>
    ///     Generates random test data of the specified size.
    /// </summary>
    /// <param name="size">The size of the data to generate.</param>
    /// <returns>A byte array containing random data.</returns>
    public static byte[] GenerateRandomData(int size)
    {
        var data = new byte[size];
        var random = new Random();
        random.NextBytes(data);
        return data;
    }

    /// <summary>
    ///     Creates a temporary file with the specified content.
    /// </summary>
    /// <param name="content">The content to write to the file.</param>
    /// <param name="extension">The file extension (default: .txt).</param>
    /// <returns>The path to the created temporary file.</returns>
    public static string CreateTempFile(string content, string extension = ".txt")
    {
        var tempPath = Path.GetTempPath();
        var fileName = $"test-{Guid.NewGuid():N}{extension}";
        var fullPath = Path.Combine(tempPath, fileName);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    /// <summary>
    ///     Creates a temporary file with the specified binary content.
    /// </summary>
    /// <param name="content">The binary content to write to the file.</param>
    /// <param name="extension">The file extension (default: .bin).</param>
    /// <returns>The path to the created temporary file.</returns>
    public static string CreateTempFile(byte[] content, string extension = ".bin")
    {
        var tempPath = Path.GetTempPath();
        var fileName = $"test-{Guid.NewGuid():N}{extension}";
        var fullPath = Path.Combine(tempPath, fileName);
        File.WriteAllBytes(fullPath, content);
        return fullPath;
    }

    /// <summary>
    ///     Compares two byte arrays for equality.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>True if the arrays are equal, false otherwise.</returns>
    public static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        if (a.Length != b.Length) return false;

        for (var i = 0; i < a.Length; i++)
            if (a[i] != b[i])
                return false;

        return true;
    }

    /// <summary>
    ///     Waits for a condition to be true with a timeout.
    /// </summary>
    /// <param name="condition">The condition to wait for.</param>
    /// <param name="timeout">The timeout in milliseconds.</param>
    /// <param name="interval">The polling interval in milliseconds.</param>
    /// <returns>True if the condition was met, false if timed out.</returns>
    public static bool WaitForCondition(Func<bool> condition, int timeout = 5000, int interval = 100)
    {
        var stopwatch = Stopwatch.StartNew();

        while (!condition())
        {
            if (stopwatch.ElapsedMilliseconds >= timeout) return false;

            Thread.Sleep(interval);
        }

        return true;
    }
}