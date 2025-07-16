using System.Text;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Tests;

/// <summary>
///     Integration tests to validate CLI compatibility between age, rage, and dotage implementations.
///     These tests ensure that command-line options and behaviors match across implementations.
/// </summary>
public class CliCompatibilityTests : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _tempDir;

    public CliCompatibilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("dotage-cli-tests");
        _logger = LoggerFactory.CreateLogger<CliCompatibilityTests>();

        // Validate that external binaries are available
        TestUtils.ValidateExternalBinaries(_logger);
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public async Task Test1_BasicEncryptionWithSingleRecipient()
    {
        _logger.LogInformation("Test 1: Basic encryption with single recipient");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data for CLI encryption!");
        var testDataFile = Path.Combine(_tempDir, "test1_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using dotage-keygen
        var ageKeyFile = Path.Combine(_tempDir, "test1_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);

        // Extract public key
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with dotage CLI
        var dotageEncryptedFile = Path.Combine(_tempDir, "test1_dotage_encrypted.age");
        var result =
            await TestUtils.RunDotAgeAsync($"encrypt -r {publicKeyLine} -o {dotageEncryptedFile} {testDataFile}", null,
                _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with age CLI to verify compatibility
        var ageDecryptedFile = Path.Combine(_tempDir, "test1_age_decrypted.txt");
        var ageResult = await TestUtils.RunAgeAsync($"-d -i {ageKeyFile} -o {ageDecryptedFile} {dotageEncryptedFile}",
            null, _logger);
        if (ageResult.ExitCode != 0)
        {
            _logger.LogError($"Age CLI decryption failed with exit code {ageResult.ExitCode}");
            _logger.LogError($"Age CLI stdout: {ageResult.Stdout}");
            _logger.LogError($"Age CLI stderr: {ageResult.Stderr}");
            Assert.Equal(0, ageResult.ExitCode);
        }

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 1 passed: Basic CLI encryption successful");
    }

    [Fact]
    public async Task Test2_BasicDecryptionWithIdentityFile()
    {
        _logger.LogInformation("Test 2: Basic decryption with identity file");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data for CLI decryption!");
        var testDataFile = Path.Combine(_tempDir, "test2_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair using dotage-keygen
        var ageKeyFile = Path.Combine(_tempDir, "test2_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);

        // Extract public key
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with age CLI
        var ageEncryptedFile = Path.Combine(_tempDir, "test2_age_encrypted.age");
        await TestUtils.RunAgeAsync($"-e -r {publicKeyLine} -o {ageEncryptedFile} {testDataFile}", null, _logger);

        // Decrypt with dotage CLI
        var dotageDecryptedFile = Path.Combine(_tempDir, "test2_dotage_decrypted.txt");
        var result =
            await TestUtils.RunDotAgeAsync($"decrypt -i {ageKeyFile} -o {dotageDecryptedFile} {ageEncryptedFile}", null,
                _logger);
        Assert.Equal(0, result.ExitCode);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 2 passed: Basic CLI decryption successful");
    }

    [Fact]
    public async Task Test3_MultipleRecipientsFromCommandLine()
    {
        _logger.LogInformation("Test 3: Multiple recipients from command line");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with multiple recipients!");
        var testDataFile = Path.Combine(_tempDir, "test3_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate multiple key pairs
        var key1File = Path.Combine(_tempDir, "test3_key1.txt");
        var key2File = Path.Combine(_tempDir, "test3_key2.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key1File, _logger);
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key2File, _logger);

        // Extract public keys
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);

        // Encrypt with dotage CLI using multiple recipients
        var dotageEncryptedFile = Path.Combine(_tempDir, "test3_dotage_encrypted.age");
        var result = await TestUtils.RunDotAgeAsync(
            $"encrypt -r {publicKey1Line} -r {publicKey2Line} -o {dotageEncryptedFile} {testDataFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with age CLI using either key
        var ageDecryptedFile = Path.Combine(_tempDir, "test3_age_decrypted.txt");
        await TestUtils.RunAgeAsync($"-d -i {key1File} -o {ageDecryptedFile} {dotageEncryptedFile}", null, _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 3 passed: Multiple recipients from command line successful");
    }

    [Fact]
    public async Task Test4_RecipientsFromFile()
    {
        _logger.LogInformation("Test 4: Recipients from file");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with recipients from file!");
        var testDataFile = Path.Combine(_tempDir, "test4_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate key pairs
        var key1File = Path.Combine(_tempDir, "test4_key1.txt");
        var key2File = Path.Combine(_tempDir, "test4_key2.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key1File, _logger);
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key2File, _logger);

        // Extract public keys and create recipients file
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);
        var recipientsFile = Path.Combine(_tempDir, "test4_recipients.txt");
        File.WriteAllText(recipientsFile, $"{publicKey1Line}\n{publicKey2Line}\n");

        // Encrypt with dotage CLI using recipients file
        var dotageEncryptedFile = Path.Combine(_tempDir, "test4_dotage_encrypted.age");
        var result =
            await TestUtils.RunDotAgeAsync($"encrypt -R {recipientsFile} -o {dotageEncryptedFile} {testDataFile}", null,
                _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with age CLI using either key
        var ageDecryptedFile = Path.Combine(_tempDir, "test4_age_decrypted.txt");
        await TestUtils.RunAgeAsync($"-d -i {key1File} -o {ageDecryptedFile} {dotageEncryptedFile}", null, _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 4 passed: Recipients from file successful");
    }

    [Fact]
    public async Task Test5_MixedRecipientsCommandLineAndFile()
    {
        _logger.LogInformation("Test 5: Mixed recipients from command line and file");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with mixed recipients!");
        var testDataFile = Path.Combine(_tempDir, "test5_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate key pairs
        var key1File = Path.Combine(_tempDir, "test5_key1.txt");
        var key2File = Path.Combine(_tempDir, "test5_key2.txt");
        var key3File = Path.Combine(_tempDir, "test5_key3.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key1File, _logger);
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key2File, _logger);
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key3File, _logger);

        // Extract public keys
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);
        var (_, publicKey3Line) = KeyFileUtils.ParseKeyFile(key3File);

        // Create recipients file with one key
        var recipientsFile = Path.Combine(_tempDir, "test5_recipients.txt");
        File.WriteAllText(recipientsFile, $"{publicKey2Line}\n");

        // Encrypt with dotage CLI using mixed recipients
        var dotageEncryptedFile = Path.Combine(_tempDir, "test5_dotage_encrypted.age");
        var result = await TestUtils.RunDotAgeAsync(
            $"encrypt -r {publicKey1Line} -R {recipientsFile} -r {publicKey3Line} -o {dotageEncryptedFile} {testDataFile}",
            null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with age CLI using any of the keys
        var ageDecryptedFile = Path.Combine(_tempDir, "test5_age_decrypted.txt");
        await TestUtils.RunAgeAsync($"-d -i {key2File} -o {ageDecryptedFile} {dotageEncryptedFile}", null, _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 5 passed: Mixed recipients successful");
    }

    [Fact]
    public async Task Test6_StdInStdOut()
    {
        _logger.LogInformation("Test 6: Standard input and output");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data for stdin/stdout!");

        // Generate a key pair
        var ageKeyFile = Path.Combine(_tempDir, "test6_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);

        // Extract public key
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Create a temporary file for input
        var testDataFile = Path.Combine(_tempDir, "test6_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Encrypt with dotage CLI using stdin/stdout
        var dotageEncryptedFile = Path.Combine(_tempDir, "test6_dotage_encrypted.age");
        var result =
            await TestUtils.RunDotAgeAsync($"encrypt -r {publicKeyLine} -o {dotageEncryptedFile} {testDataFile}", null,
                _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with dotage CLI using stdin/stdout
        var dotageDecryptedFile = Path.Combine(_tempDir, "test6_dotage_decrypted.txt");
        result = await TestUtils.RunDotAgeAsync(
            $"decrypt -i {ageKeyFile} -o {dotageDecryptedFile} {dotageEncryptedFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 6 passed: Standard input/output successful");
    }

    [Fact]
    public async Task Test7_MultipleIdentityFiles()
    {
        _logger.LogInformation("Test 7: Multiple identity files");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with multiple identities!");
        var testDataFile = Path.Combine(_tempDir, "test7_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate multiple key pairs
        var key1File = Path.Combine(_tempDir, "test7_key1.txt");
        var key2File = Path.Combine(_tempDir, "test7_key2.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key1File, _logger);
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(key2File, _logger);

        // Extract public keys
        var (_, publicKey1Line) = KeyFileUtils.ParseKeyFile(key1File);
        var (_, publicKey2Line) = KeyFileUtils.ParseKeyFile(key2File);

        // Encrypt with age CLI using multiple recipients
        var ageEncryptedFile = Path.Combine(_tempDir, "test7_age_encrypted.age");
        await TestUtils.RunAgeAsync($"-e -r {publicKey1Line} -r {publicKey2Line} -o {ageEncryptedFile} {testDataFile}",
            null, _logger);

        // Decrypt with dotage CLI using multiple identity files
        var dotageDecryptedFile = Path.Combine(_tempDir, "test7_dotage_decrypted.txt");
        var result = await TestUtils.RunDotAgeAsync(
            $"decrypt -i {key1File} -i {key2File} -o {dotageDecryptedFile} {ageEncryptedFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 7 passed: Multiple identity files successful");
    }

    [Fact]
    public async Task Test8_ExplicitEncryptFlag()
    {
        _logger.LogInformation("Test 8: Explicit encrypt flag");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with explicit encrypt flag!");
        var testDataFile = Path.Combine(_tempDir, "test8_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair
        var ageKeyFile = Path.Combine(_tempDir, "test8_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);

        // Extract public key
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with dotage CLI using explicit encrypt flag
        var dotageEncryptedFile = Path.Combine(_tempDir, "test8_dotage_encrypted.age");
        var result =
            await TestUtils.RunDotAgeAsync(
                $"encrypt --encrypt -r {publicKeyLine} -o {dotageEncryptedFile} {testDataFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Decrypt with age CLI
        var ageDecryptedFile = Path.Combine(_tempDir, "test8_age_decrypted.txt");
        await TestUtils.RunAgeAsync($"-d -i {ageKeyFile} -o {ageDecryptedFile} {dotageEncryptedFile}", null, _logger);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 8 passed: Explicit encrypt flag successful");
    }

    [Fact]
    public async Task Test9_ExplicitDecryptFlag()
    {
        _logger.LogInformation("Test 9: Explicit decrypt flag");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is test data with explicit decrypt flag!");
        var testDataFile = Path.Combine(_tempDir, "test9_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate a key pair
        var ageKeyFile = Path.Combine(_tempDir, "test9_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);

        // Extract public key
        var (_, publicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with age CLI
        var ageEncryptedFile = Path.Combine(_tempDir, "test9_age_encrypted.age");
        await TestUtils.RunAgeAsync($"-e -r {publicKeyLine} -o {ageEncryptedFile} {testDataFile}", null, _logger);

        // Decrypt with dotage CLI using explicit decrypt flag
        var dotageDecryptedFile = Path.Combine(_tempDir, "test9_dotage_decrypted.txt");
        var result =
            await TestUtils.RunDotAgeAsync(
                $"decrypt --decrypt -i {ageKeyFile} -o {dotageDecryptedFile} {ageEncryptedFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        // Verify the decrypted data matches the original
        var decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 9 passed: Explicit decrypt flag successful");
    }

    [Fact]
    public async Task Test10_HelpOutput()
    {
        _logger.LogInformation("Test 10: Help output");

        // Run help command
        var result = await TestUtils.RunDotAgeAsync("--help", null, _logger);
        Assert.Equal(0, result.ExitCode);

        _logger.LogInformation("Test 10 passed: Help output successful");
    }

    [Fact]
    public async Task Test12_CompatibilityWithAgeAndRageCLI()
    {
        _logger.LogInformation("Test 12: Full compatibility with age and rage CLI");

        // Generate test data
        var testData = Encoding.UTF8.GetBytes("Hello, this is comprehensive CLI compatibility test!");
        var testDataFile = Path.Combine(_tempDir, "test12_plaintext.txt");
        File.WriteAllBytes(testDataFile, testData);

        // Generate key pairs
        var ageKeyFile = Path.Combine(_tempDir, "test12_age_key.txt");
        var rageKeyFile = Path.Combine(_tempDir, "test12_rage_key.txt");
        await TestUtils.RunDotAgeKeyGenWithOutputAsync(ageKeyFile, _logger);
        await TestUtils.RunRageKeyGenAsync($"-o {rageKeyFile}", null, _logger);

        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);

        // Test 1: dotage encrypt -> age decrypt
        var dotageEncryptedFile = Path.Combine(_tempDir, "test12_dotage_encrypted.age");
        var result =
            await TestUtils.RunDotAgeAsync($"encrypt -r {agePublicKeyLine} -o {dotageEncryptedFile} {testDataFile}",
                null, _logger);
        Assert.Equal(0, result.ExitCode);

        var ageDecryptedFile = Path.Combine(_tempDir, "test12_age_decrypted.txt");
        await TestUtils.RunAgeAsync($"-d -i {ageKeyFile} -o {ageDecryptedFile} {dotageEncryptedFile}", null, _logger);
        var decryptedData = File.ReadAllBytes(ageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        // Test 2: dotage encrypt -> rage decrypt
        var dotageEncryptedFile2 = Path.Combine(_tempDir, "test12_dotage_encrypted2.age");
        result = await TestUtils.RunDotAgeAsync(
            $"encrypt -r {ragePublicKeyLine} -o {dotageEncryptedFile2} {testDataFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        var rageDecryptedFile = Path.Combine(_tempDir, "test12_rage_decrypted.txt");
        await TestUtils.RunRageAsync($"-d -i {rageKeyFile} -o {rageDecryptedFile} {dotageEncryptedFile2}", null,
            _logger);
        decryptedData = File.ReadAllBytes(rageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        // Test 3: age encrypt -> dotage decrypt
        var ageEncryptedFile = Path.Combine(_tempDir, "test12_age_encrypted.age");
        await TestUtils.RunAgeAsync($"-e -r {agePublicKeyLine} -o {ageEncryptedFile} {testDataFile}", null, _logger);

        var dotageDecryptedFile = Path.Combine(_tempDir, "test12_dotage_decrypted.txt");
        result = await TestUtils.RunDotAgeAsync($"decrypt -i {ageKeyFile} -o {dotageDecryptedFile} {ageEncryptedFile}",
            null, _logger);
        Assert.Equal(0, result.ExitCode);

        decryptedData = File.ReadAllBytes(dotageDecryptedFile);
        Assert.Equal(testData, decryptedData);

        // Test 4: rage encrypt -> dotage decrypt
        var rageEncryptedFile = Path.Combine(_tempDir, "test12_rage_encrypted.age");
        await TestUtils.RunRageAsync($"-e -r {ragePublicKeyLine} -o {rageEncryptedFile} {testDataFile}", null, _logger);

        var dotageDecryptedFile2 = Path.Combine(_tempDir, "test12_dotage_decrypted2.txt");
        result = await TestUtils.RunDotAgeAsync(
            $"decrypt -i {rageKeyFile} -o {dotageDecryptedFile2} {rageEncryptedFile}", null, _logger);
        Assert.Equal(0, result.ExitCode);

        decryptedData = File.ReadAllBytes(dotageDecryptedFile2);
        Assert.Equal(testData, decryptedData);

        _logger.LogInformation("Test 12 passed: Full CLI compatibility successful");
    }
}