namespace DotAge.Core.Crypto;

/// <summary>
///     Cryptographic constants used across the DotAge.Core library.
/// </summary>
public static class CryptoConstants
{
    /// <summary>
    ///     Standard file key size in bytes (16 bytes).
    /// </summary>
    public const int FileKeySize = 16;

    /// <summary>
    ///     Standard nonce size in bytes (12 bytes) for ChaCha20Poly1305.
    /// </summary>
    public const int NonceSize = 12;

    /// <summary>
    ///     Stream nonce size in bytes (16 bytes) for payload encryption.
    ///     Reference: age Go implementation uses streamNonceSize = 16
    /// </summary>
    public const int StreamNonceSize = 16;

    /// <summary>
    ///     Standard key size in bytes (32 bytes).
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    ///     Standard salt size in bytes (16 bytes).
    /// </summary>
    public const int SaltSize = 16;
}