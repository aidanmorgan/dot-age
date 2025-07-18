using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Tests;

/// <summary>
///     Tests for security features including secure memory handling and passphrase encryption.
/// </summary>
public class SecurityTests : IDisposable
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);
    private readonly ILogger _logger;
    private readonly string _tempDir;

    public SecurityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("security-tests");
        _logger = LoggerFactory.CreateLogger<SecurityTests>();
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public void SecureMemoryUtils_ClearsSensitiveData()
    {
        // Arrange
        var sensitiveData = Encoding.UTF8.GetBytes("very-secret-key-data");
        var originalData = new byte[sensitiveData.Length];
        sensitiveData.CopyTo(originalData, 0);

        // Act
        SecureMemoryUtils.ClearSensitiveData(sensitiveData);

        // Assert - Data should be cleared (not equal to original)
        Assert.NotEqual(originalData, sensitiveData);

        // Should be all zeros after clearing
        Assert.All(sensitiveData, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SecureByteArray_DisposeProperly()
    {
        // Arrange
        var originalData = Encoding.UTF8.GetBytes("secret-data");
        var dataCopy = new byte[originalData.Length];
        originalData.CopyTo(dataCopy, 0);

        // Act
        using var secureArray = SecureMemoryUtils.CreateSecureByteArray(dataCopy);

        // Assert - Should be accessible while not disposed
        Assert.Equal(originalData, secureArray.Data);
        Assert.Equal(originalData.Length, secureArray.Length);

        // After dispose, data should be cleared
        secureArray.Dispose();
        Assert.NotEqual(originalData, dataCopy);
    }

    [Fact]
    public void SecureByteArray_ThrowsAfterDispose()
    {
        // Arrange
        var data = Encoding.UTF8.GetBytes("test-data");
        var secureArray = SecureMemoryUtils.CreateSecureByteArray(data);

        // Act
        secureArray.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() => secureArray.Data);
        Assert.Equal(0, secureArray.Length); // Should return 0 when disposed
    }

    [Fact]
    public void Age_EncryptDecrypt_WithSensitiveDataClearing_Works()
    {
        // Arrange
        var age = new Age();
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        age.AddRecipient(new X25519Recipient(publicKey));

        var originalMessage = "Secret message that should be handled securely";
        var plaintext = Encoding.UTF8.GetBytes(originalMessage);

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);
        Assert.NotNull(ciphertext);

        // Decrypt
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decrypted = decryptAge.Decrypt(ciphertext);

        // Assert
        var decryptedMessage = Encoding.UTF8.GetString(decrypted);
        Assert.Equal(originalMessage, decryptedMessage);
    }

    [Fact]
    public void ChaCha20Poly1305_WithSecureMemory_Works()
    {
        // Arrange
        var key = RandomUtils.GenerateRandomBytes(32);
        var nonce = RandomUtils.GenerateRandomBytes(12);
        var plaintext = Encoding.UTF8.GetBytes("Test message for ChaCha20Poly1305");

        try
        {
            // Act
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);
            var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            // Ensure sensitive data is cleared
            SecureMemoryUtils.ClearSensitiveData(key);
            SecureMemoryUtils.ClearSensitiveData(nonce);
        }
    }

    [Fact]
    public async Task BasicPassphraseEncryptionDecryption()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-passphrase-123";
        var plaintext = Encoding.UTF8.GetBytes("Hello, this is a test message for passphrase encryption!");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Assert - Verify ciphertext is different from plaintext
        Assert.NotEqual(plaintext, ciphertext);
        Assert.True(ciphertext.Length > plaintext.Length);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task PassphraseEncryptionWithDifferentPassphrases()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase1 = "correct-passphrase";
        var passphrase2 = "wrong-passphrase";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase1)), cts.Token);

        // Act - Encrypt with correct passphrase
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act & Assert - Try to decrypt with wrong passphrase
        var wrongAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => wrongAge.AddIdentity(new ScryptRecipient(passphrase2)), cts.Token);

        await Assert.ThrowsAsync<AgeDecryptionException>(async () =>
            await Task.Run(() => wrongAge.Decrypt(ciphertext), cts.Token));
    }

    [Fact]
    public async Task PassphraseEncryptionWithEmptyPassphrase()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "";
        var age = await Task.Run(() => new Age(), cts.Token);

        // Act & Assert - Should throw when creating ScryptRecipient with empty passphrase
        await Assert.ThrowsAsync<AgeKeyException>(async () =>
            await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token));
    }

    [Fact]
    public async Task PassphraseEncryptionWithNullPassphrase()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        string? passphrase = null;
        var age = await Task.Run(() => new Age(), cts.Token);

        // Act & Assert - Should throw when creating ScryptRecipient with null passphrase
        await Assert.ThrowsAsync<AgeKeyException>(async () =>
            await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase!)), cts.Token));
    }

    [Fact]
    public async Task PassphraseEncryptionWithLongPassphrase()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = new string('x', 1000); // Very long passphrase
        var plaintext = Encoding.UTF8.GetBytes("Test data with long passphrase");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task PassphraseEncryptionWithSpecialCharacters()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
        var plaintext = Encoding.UTF8.GetBytes("Test data with special characters in passphrase");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task PassphraseEncryptionWithUnicodeCharacters()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "🔐🔒🔑密码パスワードكلمةالمرور";
        var plaintext = Encoding.UTF8.GetBytes("Test data with unicode passphrase");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task PassphraseEncryptionWithLargeData()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-passphrase-large-data";
        var plaintext = new byte[1024 * 1024]; // 1MB of data
        new Random(42).NextBytes(plaintext); // Fill with random data

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task PassphraseEncryptionWithEmptyData()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-passphrase-empty";
        var plaintext = new byte[0];

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted = await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }
}