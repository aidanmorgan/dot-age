using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;

namespace DotAge.Tests;

/// <summary>
///     Integration tests to validate compatibility between rage and dotage implementations.
///     These tests ensure that data encrypted with rage can be decrypted with dotage and vice versa, and that key interop
///     works.
/// </summary>
public class RageCompatibilityTests : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _tempDir;

    public RageCompatibilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("dotage-rage-tests");
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
        _logger = loggerFactory.CreateLogger<RageCompatibilityTests>();
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public async Task Test1_DataEncryptedWithRageCanBeDecryptedWithDotAge()
    {
        _logger.LogInformation("Test 1: Data encrypted with rage can be decrypted with dotage");
        var testData =
            Encoding.UTF8.GetBytes("Hello, this is test data encrypted with rage and decrypted with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test1_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var rageKeyFile = Path.Combine(_tempDir, "test1_key.txt");
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-rage1", $"-o {rageKeyFile}", _logger);
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var publicKey = KeyFileUtils.DecodeAgePublicKey(publicKeyLine);
        var rageEncryptedFile = Path.Combine(_tempDir, "test1_rage_encrypted.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {publicKeyLine} -o {rageEncryptedFile} {testDataFile}", null,
            _logger);
        var dotageDecryptedFile = Path.Combine(_tempDir, "test1_dotage_decrypted.txt");
        var (privateKeyBytes, _) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey, privateKeyBytes));
        age.DecryptFile(rageEncryptedFile, dotageDecryptedFile);
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 1 passed: rage -> dotage decryption successful");
    }

    [Fact]
    public async Task Test2_DataEncryptedWithDotAgeCanBeDecryptedWithRage()
    {
        _logger.LogInformation("Test 2: Data encrypted with dotage can be decrypted with rage");
        var testData =
            Encoding.UTF8.GetBytes("Hello, this is test data encrypted with dotage and decrypted with rage!");
        var testDataFile = Path.Combine(_tempDir, "test2_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var rageKeyFile = Path.Combine(_tempDir, "test2_key.txt");
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-rage2", $"-o {rageKeyFile}", _logger);
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var dotageEncryptedFile = Path.Combine(_tempDir, "test2_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKeyBytes));
        age.EncryptFile(testDataFile, dotageEncryptedFile);
        var rageDecryptedFile = Path.Combine(_tempDir, "test2_rage_decrypted.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecryptedFile} {dotageEncryptedFile}",
            null, _logger);
        var decryptedData = File.ReadAllBytes(rageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 2 passed: dotage -> rage decryption successful");
    }

    [Fact]
    public async Task Test3_KeysGeneratedWithRageKeygenCanBeUsedWithDotAge()
    {
        _logger.LogInformation(
            "Test 3: Keys generated with rage-keygen can be used to encrypt and decrypt with dotage");
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data using rage-keygen keys with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test3_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var rageKeyFile = Path.Combine(_tempDir, "test3_key.txt");
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-rage3", $"-o {rageKeyFile}", _logger);
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (privateKeyBytes, publicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var dotageEncryptedFile = Path.Combine(_tempDir, "test3_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKeyBytes));
        age.EncryptFile(testDataFile, dotageEncryptedFile);
        var dotageDecryptedFile = Path.Combine(_tempDir, "test3_dotage_decrypted.txt");
        age = new Age();
        age.AddIdentity(new X25519Recipient(publicKeyBytes, privateKeyBytes));
        age.DecryptFile(dotageEncryptedFile, dotageDecryptedFile);
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 3 passed: rage-keygen keys work with dotage");
    }

    [Fact]
    public async Task Test4_KeysGeneratedWithDotAgeKeygenCanBeUsedWithRage()
    {
        _logger.LogInformation(
            "Test 4: Keys generated with dotage-keygen can be used to encrypt and decrypt with rage");
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data using dotage-keygen keys with rage!");
        var testDataFile = Path.Combine(_tempDir, "test4_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var dotageKeyFile = Path.Combine(_tempDir, "test4_key.txt");
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var privateKeyAge = KeyFileUtils.EncodeAgeSecretKey(privateKey);
        var publicKeyAge = KeyFileUtils.EncodeAgePublicKey(publicKey);
        var keyOutput =
            $"# created: {DateTime.UtcNow:o} by DotAge 0.0.1-alpha\n# public key: {publicKeyAge}\n{privateKeyAge}";
        File.WriteAllText(dotageKeyFile, keyOutput);
        var rageEncryptedFile = Path.Combine(_tempDir, "test4_rage_encrypted.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {publicKeyAge} -o {rageEncryptedFile} {testDataFile}", null,
            _logger);
        var rageDecryptedFile = Path.Combine(_tempDir, "test4_rage_decrypted.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {dotageKeyFile} -o {rageDecryptedFile} {rageEncryptedFile}",
            null, _logger);
        var decryptedData = File.ReadAllBytes(rageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 4 passed: dotage-keygen keys work with rage");
    }

    [Fact]
    public async Task Test5_ScryptPassphraseCompatibility()
    {
        _logger.LogInformation("Test 5: Scrypt passphrase compatibility with rage");
        var testData =
            Encoding.UTF8.GetBytes(
                "Hello, this is test data encrypted with rage passphrase and decrypted with dotage!");
        var testDataFile = Path.Combine(_tempDir, "test5_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var rageEncryptedFile = Path.Combine(_tempDir, "test5_rage_encrypted.age");
        await TestUtils.RunCommandWithExpectAsync("rage",
            "test-passphrase-scrypt-rage", $"-e -p -o {rageEncryptedFile} {testDataFile}", _logger);
        var dotageDecryptedFile = Path.Combine(_tempDir, "test5_dotage_decrypted.txt");
        var age = new Age();
        age.AddIdentity(new ScryptRecipient("test-passphrase-scrypt-rage"));
        age.DecryptFile(rageEncryptedFile, dotageDecryptedFile);
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 5 passed: rage passphrase -> dotage decryption successful");
    }

    [Fact]
    public async Task Test6_ScryptPassphraseReverseCompatibility()
    {
        _logger.LogInformation("Test 6: Scrypt passphrase reverse compatibility with rage");
        var testData =
            Encoding.UTF8.GetBytes(
                "Hello, this is test data encrypted with dotage passphrase and decrypted with rage!");
        var testDataFile = Path.Combine(_tempDir, "test6_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var dotageEncryptedFile = Path.Combine(_tempDir, "test6_dotage_encrypted.age");
        var age = new Age();
        age.AddRecipient(new ScryptRecipient("test-passphrase-scrypt-reverse-rage"));
        age.EncryptFile(testDataFile, dotageEncryptedFile);
        var rageDecryptedFile = Path.Combine(_tempDir, "test6_rage_decrypted.txt");
        await TestUtils.RunCommandWithExpectAsync("rage",
            "test-passphrase-scrypt-reverse-rage", $"-d -o {rageDecryptedFile} {dotageEncryptedFile}", _logger);
        var decryptedData = File.ReadAllBytes(rageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 6 passed: dotage passphrase -> rage decryption successful");
    }

    [Fact]
    public async Task Test7_LargeFileCompatibility()
    {
        _logger.LogInformation("Test 7: Large file compatibility with rage");
        var testData = new byte[1024 * 1024];
        var random = new Random(42);
        random.NextBytes(testData);
        var testDataFile = Path.Combine(_tempDir, "test7_plaintext.bin");
        File.WriteAllBytes(testDataFile, testData);
        var rageKeyFile = Path.Combine(_tempDir, "test7_key.txt");
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-large-rage",
            $"-o {rageKeyFile}", _logger);
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var publicKey = KeyFileUtils.DecodeAgePublicKey(publicKeyLine);
        var rageEncryptedFile = Path.Combine(_tempDir, "test7_rage_encrypted.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {publicKeyLine} -o {rageEncryptedFile} {testDataFile}", null,
            _logger);
        var dotageDecryptedFile = Path.Combine(_tempDir, "test7_dotage_decrypted.bin");
        var (privateKeyBytes, _) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey, privateKeyBytes));
        age.DecryptFile(rageEncryptedFile, dotageDecryptedFile);
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 7 passed: Large file rage -> dotage decryption successful");
    }

    [Fact]
    public async Task Test8_MultipleRecipientsCompatibility()
    {
        _logger.LogInformation("Test 8: Multiple recipients compatibility with rage");
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with multiple recipients!");
        var testDataFile = Path.Combine(_tempDir, "test8_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);
        var key1File = Path.Combine(_tempDir, "test8_key1.txt");
        var key2File = Path.Combine(_tempDir, "test8_key2.txt");
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-multi1-rage",
            $"-o {key1File}", _logger);
        await TestUtils.RunCommandWithExpectAsync("rage-keygen", "test-passphrase-multi2-rage",
            $"-o {key2File}", _logger);
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);
        var rageEncryptedFile = Path.Combine(_tempDir, "test8_rage_encrypted.age");
        await TestUtils.RunCommandAsync("rage",
            $"-e -r {publicKey1Line} -r {publicKey2Line} -o {rageEncryptedFile} {testDataFile}", null, _logger);
        var dotageDecryptedFile = Path.Combine(_tempDir, "test8_dotage_decrypted.txt");
        var (privateKey1Bytes, publicKey1Bytes) = KeyFileUtils.ParseKeyFileAsBytes(key1File);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(publicKey1Bytes, privateKey1Bytes));
        age.DecryptFile(rageEncryptedFile, dotageDecryptedFile);
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);
        _logger.LogInformation("Test 8 passed: Multiple recipients rage -> dotage decryption successful");
    }
}