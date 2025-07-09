using System.Security.Cryptography;
using System.Text;
using DotAge.Core;
using DotAge.Core.Recipients;
using DotAge.Core.Exceptions;

namespace DotAge.Tests;

public class PassphraseEncryptionTests : IDisposable
{
    private readonly string _tempDir;

    public PassphraseEncryptionTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("passphrase-tests");
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public void BasicPassphraseEncryptionDecryption()
    {
        // Arrange
        var passphrase = "test-passphrase-123";
        var plaintext = Encoding.UTF8.GetBytes("Hello, this is a test message for passphrase encryption!");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Assert - Verify ciphertext is different from plaintext
        Assert.NotEqual(plaintext, ciphertext);
        Assert.True(ciphertext.Length > plaintext.Length);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionWithDifferentPassphrases()
    {
        // Arrange
        var passphrase1 = "correct-passphrase";
        var passphrase2 = "wrong-passphrase";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase1));

        // Act - Encrypt with correct passphrase
        var ciphertext = age.Encrypt(plaintext);

        // Act & Assert - Try to decrypt with wrong passphrase
        var wrongAge = new Age();
        wrongAge.AddIdentity(new ScryptRecipient(passphrase2));

        Assert.Throws<AgeDecryptionException>(() => wrongAge.Decrypt(ciphertext));
    }

    [Fact]
    public void PassphraseEncryptionWithEmptyPassphrase()
    {
        // Arrange
        var passphrase = "";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = new Age();

        // Act & Assert - Should throw when creating ScryptRecipient with empty passphrase
        Assert.Throws<AgeKeyException>(() => age.AddRecipient(new ScryptRecipient(passphrase)));
    }

    [Fact]
    public void PassphraseEncryptionWithNullPassphrase()
    {
        // Arrange
        string? passphrase = null;
        var age = new Age();

        // Act & Assert - Should throw when creating ScryptRecipient with null passphrase
        Assert.Throws<AgeKeyException>(() => age.AddRecipient(new ScryptRecipient(passphrase!)));
    }

    [Fact]
    public void PassphraseEncryptionWithLongPassphrase()
    {
        // Arrange
        var passphrase = new string('x', 1000); // Very long passphrase
        var plaintext = Encoding.UTF8.GetBytes("Test data with long passphrase");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionWithSpecialCharacters()
    {
        // Arrange
        var passphrase = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
        var plaintext = Encoding.UTF8.GetBytes("Test data with special characters in passphrase");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionWithUnicodeCharacters()
    {
        // Arrange
        var passphrase = "🔐🔒🔑密码パスワードكلمةالمرور";
        var plaintext = Encoding.UTF8.GetBytes("Test data with unicode passphrase");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionWithLargeData()
    {
        // Arrange
        var passphrase = "test-passphrase-large-data";
        var plaintext = new byte[1024 * 1024]; // 1MB of data
        new Random(42).NextBytes(plaintext); // Fill with random data

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionWithEmptyData()
    {
        // Arrange
        var passphrase = "test-passphrase-empty";
        var plaintext = new byte[0];

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted = decryptedAge.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void PassphraseEncryptionFileOperations()
    {
        // Arrange
        var passphrase = "test-passphrase-file";
        var plaintext = Encoding.UTF8.GetBytes("Test data for file operations");
        var inputFile = Path.Combine(_tempDir, "input.txt");
        var encryptedFile = Path.Combine(_tempDir, "encrypted.age");
        var decryptedFile = Path.Combine(_tempDir, "decrypted.txt");

        File.WriteAllBytes(inputFile, plaintext);

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt file
        age.EncryptFile(inputFile, encryptedFile);

        // Assert - Verify encrypted file exists and is different
        Assert.True(File.Exists(encryptedFile));
        var encryptedBytes = File.ReadAllBytes(encryptedFile);
        Assert.NotEqual(plaintext, encryptedBytes);

        // Act - Decrypt file
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        decryptedAge.DecryptFile(encryptedFile, decryptedFile);

        // Assert - Verify decrypted file matches original
        Assert.True(File.Exists(decryptedFile));
        var decryptedBytes = File.ReadAllBytes(decryptedFile);
        Assert.Equal(plaintext, decryptedBytes);
    }

    [Fact]
    public void PassphraseEncryptionWithMultipleIdentities()
    {
        // Arrange
        var passphrase1 = "passphrase-1";
        var passphrase2 = "passphrase-2";
        var plaintext = Encoding.UTF8.GetBytes("Test data with multiple identities");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase1));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt with first identity
        var decryptedAge1 = new Age();
        decryptedAge1.AddIdentity(new ScryptRecipient(passphrase1));
        var decrypted1 = decryptedAge1.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted1);

        // Act - Decrypt with second identity (should fail)
        var decryptedAge2 = new Age();
        decryptedAge2.AddIdentity(new ScryptRecipient(passphrase2));

        Assert.Throws<AgeDecryptionException>(() => decryptedAge2.Decrypt(ciphertext));
    }

    [Fact]
    public void PassphraseEncryptionWithMultipleRecipients()
    {
        // Arrange
        var passphrase1 = "passphrase-1";
        var passphrase2 = "passphrase-2";
        var plaintext = Encoding.UTF8.GetBytes("Test data with multiple recipients");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase1));
        age.AddRecipient(new ScryptRecipient(passphrase2));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Act - Decrypt with first passphrase
        var decryptedAge1 = new Age();
        decryptedAge1.AddIdentity(new ScryptRecipient(passphrase1));
        var decrypted1 = decryptedAge1.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted1);

        // Act - Decrypt with second passphrase
        var decryptedAge2 = new Age();
        decryptedAge2.AddIdentity(new ScryptRecipient(passphrase2));
        var decrypted2 = decryptedAge2.Decrypt(ciphertext);

        // Assert - Verify decrypted matches original
        Assert.Equal(plaintext, decrypted2);
    }

    [Fact]
    public void PassphraseEncryptionDeterministicOutput()
    {
        // Arrange
        var passphrase = "test-deterministic";
        var plaintext = Encoding.UTF8.GetBytes("Test data for deterministic output");

        // Act - Encrypt same data twice
        var age1 = new Age();
        age1.AddRecipient(new ScryptRecipient(passphrase));
        var ciphertext1 = age1.Encrypt(plaintext);

        var age2 = new Age();
        age2.AddRecipient(new ScryptRecipient(passphrase));
        var ciphertext2 = age2.Encrypt(plaintext);

        // Assert - Verify outputs are different (due to random salt)
        Assert.NotEqual(ciphertext1, ciphertext2);

        // Act - Decrypt both
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));
        var decrypted1 = decryptedAge.Decrypt(ciphertext1);
        var decrypted2 = decryptedAge.Decrypt(ciphertext2);

        // Assert - Both should decrypt to the same plaintext
        Assert.Equal(plaintext, decrypted1);
        Assert.Equal(plaintext, decrypted2);
    }

    [Fact]
    public void PassphraseEncryptionWithCorruptedData()
    {
        // Arrange
        var passphrase = "test-corrupted";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));

        // Act - Encrypt
        var ciphertext = age.Encrypt(plaintext);

        // Corrupt the ciphertext
        ciphertext[100] ^= 0xFF;

        // Act & Assert - Should throw when decrypting corrupted data
        var decryptedAge = new Age();
        decryptedAge.AddIdentity(new ScryptRecipient(passphrase));

        Assert.Throws<AgeFormatException>(() => decryptedAge.Decrypt(ciphertext));
    }

    [Fact]
    public void PassphraseEncryptionWithNoRecipients()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Test data");
        var age = new Age();

        // Act & Assert - Should throw when no recipients are specified
        Assert.Throws<AgeEncryptionException>(() => age.Encrypt(plaintext));
    }

    [Fact]
    public void PassphraseDecryptionWithNoIdentities()
    {
        // Arrange
        var passphrase = "test-no-identities";
        var plaintext = Encoding.UTF8.GetBytes("Test data");

        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));
        var ciphertext = age.Encrypt(plaintext);

        // Act & Assert - Should throw when no identities are specified
        var decryptedAge = new Age();
        Assert.Throws<AgeDecryptionException>(() => decryptedAge.Decrypt(ciphertext));
    }


    [Fact(DisplayName = "Scrypt passphrase round-trip compatibility: dotage <-> age <-> rage")]
    public async Task ScryptPassphraseRoundTripCompatibility()
    {
        // Arrange
        var passphrase = "test-passphrase-scrypt-compat";
        var plaintext = Encoding.UTF8.GetBytes("DotAge scrypt compatibility test!");
        var tempFile = Path.Combine(_tempDir, "plain.txt");
        var dotageEncrypted = Path.Combine(_tempDir, "dotage_encrypted.age");
        var ageEncrypted = Path.Combine(_tempDir, "age_encrypted.age");
        var rageEncrypted = Path.Combine(_tempDir, "rage_encrypted.age");
        var ageDecrypted = Path.Combine(_tempDir, "age_decrypted.txt");
        var rageDecrypted = Path.Combine(_tempDir, "rage_decrypted.txt");
        await File.WriteAllBytesAsync(tempFile, plaintext);

        // 1. Encrypt with dotage using static methods
        var dotage = new Age();
        dotage.AddRecipient(new ScryptRecipient(passphrase));
        var dotageCiphertext = dotage.Encrypt(plaintext);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext);

        // Decrypt with age and rage CLI (these require passphrase input)
        var ageCli = "age";
        var rageCli = "rage";

        // age decrypt
        await TestUtils.RunCommandWithExpectAsync(ageCli, passphrase, $"-d -o {ageDecrypted} {dotageEncrypted}");
        // rage decrypt
        await TestUtils.RunCommandWithExpectAsync(rageCli, passphrase, $"-d -o {rageDecrypted} {dotageEncrypted}");

        Assert.Equal(plaintext, await File.ReadAllBytesAsync(ageDecrypted));
        Assert.Equal(plaintext, await File.ReadAllBytesAsync(rageDecrypted));

        // 2. Encrypt with age CLI (requires passphrase input), decrypt with dotage
        await TestUtils.RunCommandWithExpectAsync(ageCli, passphrase, $"-e -p -o {ageEncrypted} {tempFile}");
        var dotageForDecrypt = new Age();
        dotageForDecrypt.AddIdentity(new ScryptRecipient(passphrase));
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted);
        var decrypted = dotageForDecrypt.Decrypt(ageCiphertext);
        Assert.Equal(plaintext, decrypted);

        // 3. Encrypt with rage CLI (requires passphrase input), decrypt with dotage
        await TestUtils.RunCommandWithExpectAsync(rageCli, passphrase, $"-e -p -o {rageEncrypted} {tempFile}");
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted);
        var decryptedRage = dotageForDecrypt.Decrypt(rageCiphertext);
        Assert.Equal(plaintext, decryptedRage);
    }
}