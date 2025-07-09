using System.Text;
using DotAge.Core;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using DotAge.KeyGen;
using Microsoft.Extensions.Logging;

namespace DotAge.Tests;

/// <summary>
///     Integration tests to validate compatibility between age and dotage implementations.
///     These tests ensure that data encrypted with age can be decrypted with dotage and vice versa.
/// </summary>
public class AgeCompatibilityTests : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _tempDir;

    public AgeCompatibilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("dotage-age-tests");

        var loggerFactory = LoggerFactory.Create(builder =>
            builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
        _logger = loggerFactory.CreateLogger<AgeCompatibilityTests>();
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public async Task Test1_DataEncryptedWithAgeCanBeDecryptedWithDotAge()
    {
        _logger.LogInformation("Test 1: Data encrypted with age can be decrypted with dotage");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data encrypted with age and decrypted with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test1_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using age-keygen with socat for interactive passphrase input
        var ageKeyFile = Path.Combine(_tempDir, "test1_key.txt");
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-123", $"-o {ageKeyFile}", _logger);

        // Extract public key from the key file
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var publicKey = KeyFileUtils.DecodeAgePublicKey(publicKeyLine);

        // Encrypt with age
        var ageEncryptedFile = Path.Combine(_tempDir, "test1_age_encrypted.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {publicKeyLine} -o {ageEncryptedFile} {testDataFile}", null,
            _logger);

        // Decrypt with dotage
        var dotageDecryptedFile = Path.Combine(_tempDir, "test1_dotage_decrypted.txt");
        var (privateKeyBytes, _) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);

        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey, privateKeyBytes));
        age.DecryptFile(ageEncryptedFile, dotageDecryptedFile);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 1 passed: age -> dotage decryption successful");
    }

    [Fact]
    public async Task Test2_DataEncryptedWithDotAgeCanBeDecryptedWithAge()
    {
        _logger.LogInformation("Test 2: Data encrypted with dotage can be decrypted with age");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data encrypted with dotage and decrypted with age!");
        var testDataFile = Path.Combine(_tempDir, "test2_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using age-keygen with socat for interactive passphrase input
        var ageKeyFile = Path.Combine(_tempDir, "test2_key.txt");
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-456", $"-o {ageKeyFile}", _logger);

        // Extract keys from the key file
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);

        // Encrypt with dotage
        var dotageEncryptedFile = Path.Combine(_tempDir, "test2_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKeyBytes));
        age.EncryptFile(testDataFile, dotageEncryptedFile);

        // Decrypt with age
        var ageDecryptedFile = Path.Combine(_tempDir, "test2_age_decrypted.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecryptedFile} {dotageEncryptedFile}", null,
            _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 2 passed: dotage -> age decryption successful");
    }

    [Fact]
    public async Task Test3_KeysGeneratedWithAgeKeygenCanBeUsedWithDotAge()
    {
        _logger.LogInformation("Test 3: Keys generated with age-keygen can be used to encrypt and decrypt with dotage");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data using age-keygen keys with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test3_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using age-keygen
        var ageKeyFile = Path.Combine(_tempDir, "test3_key.txt");
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-age-keygen",
            $"-o {ageKeyFile}", _logger);

        // Extract keys from the key file
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);

        // Encrypt with dotage using the age-generated public key
        var dotageEncryptedFile = Path.Combine(_tempDir, "test3_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKeyBytes));
        age.EncryptFile(testDataFile, dotageEncryptedFile);

        // Decrypt with dotage using the age-generated private key
        var dotageDecryptedFile = Path.Combine(_tempDir, "test3_dotage_decrypted.txt");
        var ageDecrypt = new Age();
        ageDecrypt.AddIdentity(new X25519Recipient(publicKeyBytes, privateKeyBytes));
        ageDecrypt.DecryptFile(dotageEncryptedFile, dotageDecryptedFile);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 3 passed: age-keygen keys work with dotage");
    }

    [Fact]
    public async Task Test4_KeysGeneratedWithDotAgeKeygenCanBeUsedWithAge()
    {
        _logger.LogInformation("Test 4: Keys generated with dotage-keygen can be used to encrypt and decrypt with age");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data using dotage-keygen keys with age!");
        var testDataFile = Path.Combine(_tempDir, "test4_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using dotage-keygen programmatically
        var dotageKeyFile = Path.Combine(_tempDir, "test4_key.txt");
        var keyContent = Program.GenerateKeyPairContent();
        File.WriteAllText(dotageKeyFile, keyContent);

        // Extract keys from the key file
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);
        var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);

        // Encrypt with age using the dotage-generated public key
        var ageEncryptedFile = Path.Combine(_tempDir, "test4_age_encrypted.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {publicKeyLine} -o {ageEncryptedFile} {testDataFile}", null,
            _logger);

        // Decrypt with age using the dotage-generated private key
        var ageDecryptedFile = Path.Combine(_tempDir, "test4_age_decrypted.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {dotageKeyFile} -o {ageDecryptedFile} {ageEncryptedFile}", null,
            _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 4 passed: dotage-keygen keys work with age");
    }

    [Fact]
    public async Task Test5_ScryptPassphraseCompatibility()
    {
        _logger.LogInformation("Test 5: Scrypt passphrase compatibility with age");

        // Generate test data
        var testData =
            Encoding.UTF8.GetBytes("Hello, this is test data encrypted with age passphrase and decrypted with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test5_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Encrypt with age using passphrase
        var ageEncryptedFile = Path.Combine(_tempDir, "test5_age_encrypted.age");
        await TestUtils.RunCommandWithExpectAsync("age",
            "test-passphrase-scrypt", $"-e -p -o {ageEncryptedFile} {testDataFile}", _logger);

        // Decrypt with dotage using passphrase
        var dotageDecryptedFile = Path.Combine(_tempDir, "test5_dotage_decrypted.txt");
        var age = new Age();
        age.AddIdentity(new ScryptRecipient("test-passphrase-scrypt"));
        age.DecryptFile(ageEncryptedFile, dotageDecryptedFile);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 5 passed: age passphrase -> dotage decryption successful");
    }

    [Fact]
    public async Task Test6_ScryptPassphraseReverseCompatibility()
    {
        _logger.LogInformation("Test 6: Scrypt passphrase reverse compatibility with age");

        // Generate test data
        var testData =
            Encoding.UTF8.GetBytes("Hello, this is test data encrypted with dotage passphrase and decrypted with age!");
        var testDataFile = Path.Combine(_tempDir, "test6_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Encrypt with dotage using passphrase
        var dotageEncryptedFile = Path.Combine(_tempDir, "test6_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new ScryptRecipient("test-passphrase-scrypt-reverse"));
        age.EncryptFile(testDataFile, dotageEncryptedFile);

        // Decrypt with age using passphrase
        var ageDecryptedFile = Path.Combine(_tempDir, "test6_age_decrypted.txt");
        await TestUtils.RunCommandWithExpectAsync("age",
            "test-passphrase-scrypt-reverse", $"-d -o {ageDecryptedFile} {dotageEncryptedFile}", _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 6 passed: dotage passphrase -> age decryption successful");
    }

    [Fact]
    public async Task Test7_LargeFileCompatibility()
    {
        _logger.LogInformation("Test 7: Large file compatibility with age");

        // Generate large test data (1MB)
        var testData = new byte[1024 * 1024];
        var random = new Random(42); // Use fixed seed for reproducible tests
        random.NextBytes(testData);
        var testDataFile = Path.Combine(_tempDir, "test7_plaintext.bin");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using age-keygen
        var ageKeyFile = Path.Combine(_tempDir, "test7_key.txt");
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-large", $"-o {ageKeyFile}", _logger);

        // Extract public key from the key file
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var publicKey = KeyFileUtils.DecodeAgePublicKey(publicKeyLine);

        // Encrypt with age
        var ageEncryptedFile = Path.Combine(_tempDir, "test7_age_encrypted.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {publicKeyLine} -o {ageEncryptedFile} {testDataFile}", null,
            _logger);

        // Decrypt with dotage
        var dotageDecryptedFile = Path.Combine(_tempDir, "test7_dotage_decrypted.bin");
        var (privateKeyBytes, _) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);

        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey, privateKeyBytes));
        age.DecryptFile(ageEncryptedFile, dotageDecryptedFile);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 7 passed: Large file age -> dotage decryption successful");
    }

    [Fact]
    public async Task Test8_MultipleRecipientsCompatibility()
    {
        _logger.LogInformation("Test 8: Multiple recipients compatibility with age");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with multiple recipients!");
        var testDataFile = Path.Combine(_tempDir, "test8_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate multiple key pairs using age-keygen
        var key1File = Path.Combine(_tempDir, "test8_key1.txt");
        var key2File = Path.Combine(_tempDir, "test8_key2.txt");
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-multi1", $"-o {key1File}", _logger);
        await TestUtils.RunCommandWithExpectAsync("age-keygen", "test-passphrase-multi2", $"-o {key2File}", _logger);

        // Extract public keys
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);

        // Encrypt with age using multiple recipients
        var ageEncryptedFile = Path.Combine(_tempDir, "test8_age_encrypted.age");
        await TestUtils.RunCommandAsync("age",
            $"-e -r {publicKey1Line} -r {publicKey2Line} -o {ageEncryptedFile} {testDataFile}", null, _logger);

        // Decrypt with dotage using either key
        var dotageDecryptedFile = Path.Combine(_tempDir, "test8_dotage_decrypted.txt");
        var (privateKey1Bytes, publicKey1Bytes) = KeyFileUtils.ParseKeyFileAsBytes(key1File);

        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey1Bytes, privateKey1Bytes));
        age.DecryptFile(ageEncryptedFile, dotageDecryptedFile);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 8 passed: Multiple recipients age -> dotage decryption successful");
    }
}