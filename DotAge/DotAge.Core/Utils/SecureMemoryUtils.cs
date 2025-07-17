using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for secure memory management of sensitive data.
/// </summary>
public static class SecureMemoryUtils
{
    /// <summary>
    ///     Securely clears sensitive data from a byte array by overwriting with random data.
    /// </summary>
    /// <param name="sensitiveData">The sensitive data to clear.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ClearSensitiveData(byte[]? sensitiveData)
    {
        if (sensitiveData == null || sensitiveData.Length == 0)
            return;

        // First pass: overwrite with random data
        RandomNumberGenerator.Fill(sensitiveData);
        
        // Second pass: overwrite with zeros
        Array.Clear(sensitiveData, 0, sensitiveData.Length);
        
        // Third pass: overwrite with 0xFF
        Array.Fill(sensitiveData, (byte)0xFF);
        
        // Final pass: overwrite with zeros again
        Array.Clear(sensitiveData, 0, sensitiveData.Length);
    }

    /// <summary>
    ///     Securely clears sensitive data from a span by overwriting with random data.
    /// </summary>
    /// <param name="sensitiveData">The sensitive data to clear.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ClearSensitiveData(Span<byte> sensitiveData)
    {
        if (sensitiveData.Length == 0)
            return;

        // First pass: overwrite with random data
        RandomNumberGenerator.Fill(sensitiveData);
        
        // Second pass: overwrite with zeros
        sensitiveData.Clear();
        
        // Third pass: overwrite with 0xFF
        sensitiveData.Fill(0xFF);
        
        // Final pass: overwrite with zeros again
        sensitiveData.Clear();
    }

    /// <summary>
    ///     Creates a secure disposable wrapper for sensitive byte arrays.
    /// </summary>
    /// <param name="sensitiveData">The sensitive data to wrap.</param>
    /// <returns>A disposable wrapper that will securely clear the data when disposed.</returns>
    public static SecureByteArray CreateSecureByteArray(byte[] sensitiveData)
    {
        return new SecureByteArray(sensitiveData);
    }
}

/// <summary>
///     A disposable wrapper for sensitive byte arrays that ensures secure cleanup.
/// </summary>
public sealed class SecureByteArray : IDisposable
{
    private byte[]? _data;
    private bool _disposed;

    internal SecureByteArray(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <summary>
    ///     Gets the underlying byte array. Throws if disposed.
    /// </summary>
    public byte[] Data
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _data!;
        }
    }

    /// <summary>
    ///     Gets the length of the underlying byte array. Returns 0 if disposed.
    /// </summary>
    public int Length => _disposed ? 0 : _data?.Length ?? 0;

    /// <summary>
    ///     Disposes the secure byte array and clears the sensitive data.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        SecureMemoryUtils.ClearSensitiveData(_data);
        _data = null;
        _disposed = true;
    }

    /// <summary>
    ///     Finalizer to ensure sensitive data is cleared even if Dispose is not called.
    /// </summary>
    ~SecureByteArray()
    {
        Dispose();
    }
}