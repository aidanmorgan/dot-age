using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DotAge.Core;
using DotAge.Core.Recipients;
using DotAge.Core.Exceptions;
using Microsoft.Extensions.Logging;
using DotAge.Core.Logging;

namespace DotAge.Tests;

public class PassphraseEncryptionTests : IDisposable
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);
    private readonly string _tempDir;
    private readonly ILogger _logger;

    static PassphraseEncryptionTests()
    {
        // Initialize logging from core LoggerFactory
        DotAge.Core.Logging.LoggerFactory.ForceTraceMode();
    }

    public PassphraseEncryptionTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("passphrase-tests");
        _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<PassphraseEncryptionTests>();
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
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
        var plaintext = Encoding.UTF8.GetBytes("Test data");

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

    [Fact]
    public async Task PassphraseEncryptionFileOperations()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-passphrase-file";
        var plaintext = Encoding.UTF8.GetBytes("Test data for file operations");
        var inputFile = Path.Combine(_tempDir, "input.txt");
        var encryptedFile = Path.Combine(_tempDir, "encrypted.age");
        var decryptedFile = Path.Combine(_tempDir, "decrypted.txt");

        File.WriteAllBytes(inputFile, plaintext);

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt file
        await Task.Run(() => age.EncryptFile(inputFile, encryptedFile), cts.Token);

        // Assert - Verify encrypted file exists and is different
        Assert.True(File.Exists(encryptedFile));
        var encryptedBytes = await File.ReadAllBytesAsync(encryptedFile, cts.Token);
        Assert.NotEqual(plaintext, encryptedBytes);

        // Act - Decrypt file
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        await Task.Run(() => decryptedAge.DecryptFile(encryptedFile, decryptedFile), cts.Token);

        // Assert - Verify decrypted file matches original
        Assert.True(File.Exists(decryptedFile));
        var decryptedBytes = await File.ReadAllBytesAsync(decryptedFile, cts.Token);
        Assert.Equal(plaintext, decryptedBytes);
    }

    [Fact]
    public async Task PassphraseEncryptionWithMultipleIdentities()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase1 = "passphrase-1";
        var passphrase2 = "passphrase-2";
        var plaintext = Encoding.UTF8.GetBytes("Test data with multiple identities");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase1)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt with first identity
        var decryptedAge1 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge1.AddIdentity(new ScryptRecipient(passphrase1)), cts.Token);
        var decrypted1 = await Task.Run(() => decryptedAge1.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted1);

        // Act - Decrypt with second identity (should fail)
        var decryptedAge2 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge2.AddIdentity(new ScryptRecipient(passphrase2)), cts.Token);

        await Assert.ThrowsAsync<AgeDecryptionException>(async () => 
            await Task.Run(() => decryptedAge2.Decrypt(ciphertext), cts.Token));
    }

    [Fact]
    public async Task PassphraseEncryptionWithMultipleRecipients()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase1 = "passphrase-1";
        var passphrase2 = "passphrase-2";
        var plaintext = Encoding.UTF8.GetBytes("Test data with multiple recipients");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase1)), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase2)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act - Decrypt with first passphrase
        var decryptedAge1 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge1.AddIdentity(new ScryptRecipient(passphrase1)), cts.Token);
        var decrypted1 = await Task.Run(() => decryptedAge1.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted1);

        // Act - Decrypt with second passphrase
        var decryptedAge2 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge2.AddIdentity(new ScryptRecipient(passphrase2)), cts.Token);
        var decrypted2 = await Task.Run(() => decryptedAge2.Decrypt(ciphertext), cts.Token);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted2);
    }

    [Fact]
    public async Task PassphraseEncryptionDeterministicOutput()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-deterministic";
        var plaintext = Encoding.UTF8.GetBytes("Test data for deterministic output");

        // Act - Encrypt same data twice
        var age1 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age1.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var ciphertext1 = await Task.Run(() => age1.Encrypt(plaintext), cts.Token);

        var age2 = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age2.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var ciphertext2 = await Task.Run(() => age2.Encrypt(plaintext), cts.Token);

        // Assert - Verify outputs are different (due to random salt)
        Assert.NotEqual(ciphertext1, ciphertext2);

        // Act - Decrypt both
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var decrypted1 = await Task.Run(() => decryptedAge.Decrypt(ciphertext1), cts.Token);
        var decrypted2 = await Task.Run(() => decryptedAge.Decrypt(ciphertext2), cts.Token);

        // Assert - Both should decrypt to the same plaintext
        Assert.Equal(plaintext, decrypted1);
        Assert.Equal(plaintext, decrypted2);
    }

    [Fact]
    public async Task PassphraseEncryptionWithCorruptedData()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-corrupted";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);

        // Act - Encrypt
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Corrupt the ciphertext
        ciphertext[100] ^= 0xFF;

        // Act & Assert - Should throw when decrypting corrupted data
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => decryptedAge.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);

        await Assert.ThrowsAsync<AgeFormatException>(async () => 
            await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token));
    }

    [Fact]
    public async Task PassphraseEncryptionWithNoRecipients()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Test data");
        var age = await Task.Run(() => new Age(), cts.Token);

        // Act & Assert - Should throw when no recipients are specified
        await Assert.ThrowsAsync<AgeEncryptionException>(async () => 
            await Task.Run(() => age.Encrypt(plaintext), cts.Token));
    }

    [Fact]
    public async Task PassphraseDecryptionWithNoIdentities()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-no-identities";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var ciphertext = await Task.Run(() => age.Encrypt(plaintext), cts.Token);

        // Act & Assert - Should throw when no identities are specified
        var decryptedAge = await Task.Run(() => new Age(), cts.Token);
        await Assert.ThrowsAsync<AgeDecryptionException>(async () => 
            await Task.Run(() => decryptedAge.Decrypt(ciphertext), cts.Token));
    }


    [Fact(DisplayName = "Scrypt passphrase round-trip compatibility: dotage <-> age <-> rage")]
    public async Task ScryptPassphraseRoundTripCompatibility()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        // Arrange
        var passphrase = "test-passphrase-scrypt-compat";
        var plaintext = Encoding.UTF8.GetBytes("DotAge scrypt compatibility test!");
        var tempFile = Path.Combine(_tempDir, "plain.txt");
        var dotageEncrypted = Path.Combine(_tempDir, "dotage_encrypted.age");
        var ageEncrypted = Path.Combine(_tempDir, "age_encrypted.age");
        var rageEncrypted = Path.Combine(_tempDir, "rage_encrypted.age");
        var ageDecrypted = Path.Combine(_tempDir, "age_decrypted.txt");
        var rageDecrypted = Path.Combine(_tempDir, "rage_decrypted.txt");
        await File.WriteAllBytesAsync(tempFile, plaintext, cts.Token);

        // 1. Encrypt with dotage using static methods
        var dotage = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => dotage.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var dotageCiphertext = await Task.Run(() => dotage.Encrypt(plaintext), cts.Token);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext, cts.Token);

        // Decrypt with age and rage CLI (these require passphrase input)
        var ageCli = "age";
        var rageCli = "rage";
        // age decrypt
        await TestUtils.RunCommandWithExpectAsync(ageCli, passphrase, $"-d -o {ageDecrypted} {dotageEncrypted}", _logger);
        // rage decrypt
        await TestUtils.RunCommandWithExpectAsync(rageCli, passphrase, $"-d -o {rageDecrypted} {dotageEncrypted}", _logger);

        Assert.Equal(plaintext, await File.ReadAllBytesAsync(ageDecrypted, cts.Token));
        Assert.Equal(plaintext, await File.ReadAllBytesAsync(rageDecrypted, cts.Token));

        // 2. Encrypt with age CLI (requires passphrase input), decrypt with dotage
        await TestUtils.RunCommandWithExpectAsync(ageCli, passphrase, $"-e -p -o {ageEncrypted} {tempFile}", _logger);
        var dotageForDecrypt = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => dotageForDecrypt.AddIdentity(new ScryptRecipient(passphrase)), cts.Token);
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted, cts.Token);
        var decrypted = await Task.Run(() => dotageForDecrypt.Decrypt(ageCiphertext), cts.Token);
        Assert.Equal(plaintext, decrypted);

        // 3. Encrypt with rage CLI (requires passphrase input), decrypt with dotage
        await TestUtils.RunCommandWithExpectAsync(rageCli, passphrase, $"-e -p -o {rageEncrypted} {tempFile}", _logger);
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted, cts.Token);
        var decryptedRage = await Task.Run(() => dotageForDecrypt.Decrypt(rageCiphertext), cts.Token);
        Assert.Equal(plaintext, decryptedRage);
    }
}