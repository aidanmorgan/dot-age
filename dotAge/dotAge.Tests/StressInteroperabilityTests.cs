using System.Security.Cryptography;
using System.Text;
using DotAge.Core;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;
using DotAge.KeyGen;
using Microsoft.Extensions.Logging;

namespace DotAge.Tests;

/// <summary>
/// Comprehensive stress tests for interoperability between age, rage, and dotage.
/// Performs 5000 randomized tests covering all permutations of encryption/decryption
/// using both generated keys and passphrases.
/// </summary>
public class StressInteroperabilityTests : IDisposable
{
    private static readonly DotAge.Cli.Program _cli = new DotAge.Cli.Program();
    private static readonly DotAge.KeyGen.Program _keyGen = new DotAge.KeyGen.Program();

    private const int DefaultStressTestCount = 10000;

    private readonly ILogger _logger;
    private readonly string _tempDir;
    private readonly Random _random;
    private int _testCount = 0;
    private int _successCount = 0;
    private int _failureCount = 0;

    public StressInteroperabilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("stress-interop-tests");
        _random = new Random(42); // Fixed seed for reproducibility

        var loggerFactory = LoggerFactory.Create(builder =>
            builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        _logger = loggerFactory.CreateLogger<StressInteroperabilityTests>();
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact(DisplayName = "Stress Test: Randomized interoperability tests")]
    public async Task StressTest_RandomizedInteroperabilityTests()
    {
        // Only run stress tests when explicitly requested
        var runStressTests = Environment.GetEnvironmentVariable("RUN_STRESS_TESTS");
        if (string.IsNullOrEmpty(runStressTests) || runStressTests.ToLower() != "true")
        {
            _logger.LogInformation("Skipping stress tests. Set RUN_STRESS_TESTS=true to run them.");
            return;
        }

        _logger.LogInformation("Starting stress test with 5000 randomized interoperability tests");
        
        var startTime = DateTime.UtcNow;
        var testTypes = new[]
        {
            "Key-based encryption/decryption",
            "Passphrase-based encryption/decryption",
            "Mixed recipients (keys + passphrases)",
            "Large data encryption/decryption",
            "Empty data encryption/decryption",
            "Unicode data encryption/decryption"
        };

        for (int i = 0; i < DefaultStressTestCount; i++)
        {
            try
            {
                var testData = GenerateRandomTestData(i);
                var passphrase = GenerateRandomPassphrase(i);

                await RunRandomizedTest(i, testData, passphrase);
                
                _successCount++;
            }
            catch (Exception ex)
            {
                var elapsed = DateTime.UtcNow - startTime;
                var successRate = (_successCount * 100.0) / (i + 1);
                _logger.LogError("Test {TestNumber} failed after {Elapsed:F1}s. Success rate: {SuccessRate:F1}% ({SuccessCount}/{TotalCount})", 
                    i, elapsed.TotalSeconds, successRate, _successCount, i + 1);
                _logger.LogError("Exception: {Exception}", ex);
                
                // Fail immediately on first exception
                throw;
            }
        }

        var totalElapsed = DateTime.UtcNow - startTime;
        var finalSuccessRate = (_successCount * 100.0) / 5000;
        
        _logger.LogInformation("Stress test completed in {TotalElapsed:F1}s", totalElapsed.TotalSeconds);
        _logger.LogInformation("Final results: {SuccessCount} successful, {FailedCount} failed out of 5000 tests", 
            _successCount, 5000 - _successCount);
        _logger.LogInformation("Final success rate: {SuccessRate:F1}%", finalSuccessRate);
        
        // Assert that success rate is above 90%
        Assert.True(finalSuccessRate >= 100.0, $"Success rate {finalSuccessRate:F1}% is below 90% threshold");
    }
    

    private async Task RunRandomizedTest(int testNumber, byte[] testData, string passphrase)
    {
        var testDir = Path.Combine(_tempDir, $"test_{testNumber}");
        Directory.CreateDirectory(testDir);
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        await File.WriteAllBytesAsync(plaintextFile, testData);

        // Define test methods and names as tuples for random selection
        var testMethods = new (string Name, Func<Task> Method)[]
        {
            // Key-based tests
            ("Key-based: DotAge -> Age -> Rage", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedDotAgeToAgeToRage(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Age -> DotAge -> Rage", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedAgeToDotAgeToRage(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Rage -> DotAge -> Age", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedRageToDotAgeToAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: DotAge -> Rage -> Age", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedDotAgeToRageToAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Age -> Rage -> DotAge", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedAgeToRageToDotAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Rage -> Age -> DotAge", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile, passphrase);
                await GenerateRageKey(rageKeyFile, passphrase);
                await GenerateDotAgeKey(dotageKeyFile, passphrase);
                
                await TestKeyBasedRageToAgeToDotAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            // Passphrase-based tests
            ("Passphrase-based: DotAge -> Age -> Rage", async () => await TestPassphraseBasedDotAgeToAgeToRage(testDir, testData, passphrase)),
            ("Passphrase-based: Age -> DotAge -> Rage", async () => await TestPassphraseBasedAgeToDotAgeToRage(testDir, testData, passphrase)),
            ("Passphrase-based: Rage -> DotAge -> Age", async () => await TestPassphraseBasedRageToDotAgeToAge(testDir, testData, passphrase)),
            ("Passphrase-based: DotAge -> Rage -> Age", async () => await TestPassphraseBasedDotAgeToRageToAge(testDir, testData, passphrase)),
            ("Passphrase-based: Age -> Rage -> DotAge", async () => await TestPassphraseBasedAgeToRageToDotAge(testDir, testData, passphrase)),
            ("Passphrase-based: Rage -> Age -> DotAge", async () => await TestPassphraseBasedRageToAgeToDotAge(testDir, testData, passphrase))
        };

        // Randomly select a test method
        var random = new Random(testNumber);
        var selectedTest = testMethods[random.Next(testMethods.Length)];
        
        _logger.LogInformation("Test {TestNumber}: Running permutation: {Permutation}", testNumber, selectedTest.Name);
        
        // Execute the randomly selected test
        await selectedTest.Method();
    }

    private async Task GenerateAgeKey(string keyFile, string passphrase)
    {
        // age-keygen doesn't prompt for passphrase when using -o flag
        await TestUtils.RunCommandAsync("age-keygen", $"-o {keyFile}");
    }

    private async Task GenerateRageKey(string keyFile, string passphrase)
    {
        // rage-keygen doesn't prompt for passphrase when using -o flag
        await TestUtils.RunCommandAsync("rage-keygen", $"-o {keyFile}");
    }

    private async Task GenerateDotAgeKey(string keyFile, string passphrase)
    {
        // Use the static method from DotAge.KeyGen.Program
        var keyContent = _keyGen.GenerateKeyPairContent();
        await File.WriteAllTextAsync(keyFile, keyContent);
    }

    // Key-based tests
    private async Task TestKeyBasedDotAgeToAgeToRage(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with dotage using age public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = new Age();
        var agePublicKey = KeyFileUtils.DecodeAgePublicKey(agePublicKeyLine);
        age.AddRecipient(new X25519Recipient(agePublicKey));
        var dotageCiphertext = age.Encrypt(testData);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext);

        // 2. Decrypt with age using age private key
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {dotageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);

        // 3. Re-encrypt with age using rage public key
        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {ragePublicKeyLine} -o {ageReEncrypted} {ageDecrypted}");

        // 4. Decrypt with rage using rage private key
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecrypted} {ageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestKeyBasedAgeToDotAgeToRage(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with age using rage public key
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {ragePublicKeyLine} -o {ageEncrypted} {plaintextFile}");

        // 2. Decrypt with dotage using rage private key
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (ragePrivateKeyBytes, ragePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(ragePublicKeyBytes, ragePrivateKeyBytes));
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted);
        var dotageDecryptedData = age.Decrypt(ageCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData);

        // 3. Re-encrypt with dotage using dotage public key
        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = new Age();
        var dotagePublicKey = KeyFileUtils.DecodeAgePublicKey(dotagePublicKeyLine);
        dotageAge.AddRecipient(new X25519Recipient(dotagePublicKey));
        var dotageReCiphertext = dotageAge.Encrypt(dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext);

        // 4. Decrypt with rage using dotage private key
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        await TestUtils.RunCommandAsync("rage", $"-d -i {dotageKeyFile} -o {rageDecrypted} {dotageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestKeyBasedRageToDotAgeToAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with rage using dotage public key
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {dotagePublicKeyLine} -o {rageEncrypted} {plaintextFile}");

        // 2. Decrypt with dotage using dotage private key
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(dotagePublicKeyBytes, dotagePrivateKeyBytes));
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted);
        var dotageDecryptedData = age.Decrypt(rageCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData);

        // 3. Re-encrypt with dotage using age public key
        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = new Age();
        var agePublicKey = KeyFileUtils.DecodeAgePublicKey(agePublicKeyLine);
        dotageAge.AddRecipient(new X25519Recipient(agePublicKey));
        var dotageReCiphertext = dotageAge.Encrypt(dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext);

        // 4. Decrypt with age using age private key
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {dotageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestKeyBasedDotAgeToRageToAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with dotage using rage public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = new Age();
        var ragePublicKey = KeyFileUtils.DecodeAgePublicKey(ragePublicKeyLine);
        age.AddRecipient(new X25519Recipient(ragePublicKey));
        var dotageCiphertext = age.Encrypt(testData);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext);

        // 2. Decrypt with rage using rage private key
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecrypted} {dotageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);

        // 3. Re-encrypt with rage using age public key
        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageReEncrypted} {rageDecrypted}");

        // 4. Decrypt with age using age private key
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {rageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestKeyBasedAgeToRageToDotAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with age using dotage public key
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {dotagePublicKeyLine} -o {ageEncrypted} {plaintextFile}");

        // 2. Decrypt with rage using dotage private key
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {dotageKeyFile} -o {rageDecrypted} {ageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);

        // 3. Re-encrypt with rage using age public key
        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageReEncrypted} {rageDecrypted}");

        // 4. Decrypt with dotage using age private key
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (agePrivateKeyBytes, agePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(agePublicKeyBytes, agePrivateKeyBytes));
        var rageReCiphertext = await File.ReadAllBytesAsync(rageReEncrypted);
        var dotageDecryptedData = age.Decrypt(rageReCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
    }

    private async Task TestKeyBasedRageToAgeToDotAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // Extract public keys
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // 1. Encrypt with rage using age public key
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageEncrypted} {plaintextFile}");

        // 2. Decrypt with age using age private key
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {rageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);

        // 3. Re-encrypt with age using dotage public key
        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {dotagePublicKeyLine} -o {ageReEncrypted} {ageDecrypted}");

        // 4. Decrypt with dotage using dotage private key
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        var age = new Age();
        age.AddIdentity(new X25519Recipient(dotagePublicKeyBytes, dotagePrivateKeyBytes));
        var ageReCiphertext = await File.ReadAllBytesAsync(ageReEncrypted);
        var dotageDecryptedData = age.Decrypt(ageReCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
    }

    // Passphrase-based tests
    private async Task TestPassphraseBasedDotAgeToAgeToRage(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with dotage using passphrase
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));
        var dotageCiphertext = age.Encrypt(testData);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext);

        // 2. Decrypt with age using passphrase
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {dotageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);

        // 3. Re-encrypt with age using passphrase
        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageReEncrypted} {ageDecrypted}");

        // 4. Decrypt with rage using passphrase
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {ageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestPassphraseBasedAgeToDotAgeToRage(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with age using passphrase
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageEncrypted} {plaintextFile}");

        // 2. Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = new Age();
        age.AddIdentity(new ScryptIdentity(passphrase));
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted);
        var dotageDecryptedData = age.Decrypt(ageCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData);

        // 3. Re-encrypt with dotage using passphrase
        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = new Age();
        dotageAge.AddRecipient(new ScryptRecipient(passphrase));
        var dotageReCiphertext = dotageAge.Encrypt(dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext);

        // 4. Decrypt with rage using passphrase
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {dotageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestPassphraseBasedRageToDotAgeToAge(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with rage using passphrase
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageEncrypted} {plaintextFile}");

        // 2. Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = new Age();
        age.AddIdentity(new ScryptIdentity(passphrase));
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted);
        var dotageDecryptedData = age.Decrypt(rageCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData);

        // 3. Re-encrypt with dotage using passphrase
        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = new Age();
        dotageAge.AddRecipient(new ScryptRecipient(passphrase));
        var dotageReCiphertext = dotageAge.Encrypt(dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext);

        // 4. Decrypt with age using passphrase
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {dotageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestPassphraseBasedDotAgeToRageToAge(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with dotage using passphrase
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = new Age();
        age.AddRecipient(new ScryptRecipient(passphrase));
        var dotageCiphertext = age.Encrypt(testData);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext);

        // 2. Decrypt with rage using passphrase
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {dotageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);

        // 3. Re-encrypt with rage using passphrase
        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageReEncrypted} {rageDecrypted}");

        // 4. Decrypt with age using passphrase
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {rageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestPassphraseBasedAgeToRageToDotAge(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with age using passphrase
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageEncrypted} {plaintextFile}");

        // 2. Decrypt with rage using passphrase
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {ageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted);
        Assert.Equal(testData, rageDecryptedData);

        // 3. Re-encrypt with rage using passphrase
        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageReEncrypted} {rageDecrypted}");

        // 4. Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = new Age();
        age.AddIdentity(new ScryptIdentity(passphrase));
        var rageReCiphertext = await File.ReadAllBytesAsync(rageReEncrypted);
        var dotageDecryptedData = age.Decrypt(rageReCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
    }

    private async Task TestPassphraseBasedRageToAgeToDotAge(string testDir, byte[] testData, string passphrase)
    {
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        // 1. Encrypt with rage using passphrase
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageEncrypted} {plaintextFile}");

        // 2. Decrypt with age using passphrase
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {rageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted);
        Assert.Equal(testData, ageDecryptedData);

        // 3. Re-encrypt with age using passphrase
        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageReEncrypted} {ageDecrypted}");

        // 4. Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = new Age();
        age.AddIdentity(new ScryptIdentity(passphrase));
        var ageReCiphertext = await File.ReadAllBytesAsync(ageReEncrypted);
        var dotageDecryptedData = age.Decrypt(ageReCiphertext);
        Assert.Equal(testData, dotageDecryptedData);
    }

    private byte[] GenerateRandomTestData(int seed)
    {
        var random = new Random(seed);
        var dataSize = random.Next(1, 1024 * 1024); // 1 byte to 1MB
        var data = new byte[dataSize];
        random.NextBytes(data);
        
        // Occasionally add some text data for better coverage
        if (random.Next(10) == 0)
        {
            var text = $"Test data with seed {seed} and random text: {Guid.NewGuid()}";
            data = Encoding.UTF8.GetBytes(text);
        }
        
        return data;
    }

    private string GenerateRandomPassphrase(int seed)
    {
        var random = new Random(seed);
        var length = random.Next(8, 64);
        // Use only ASCII-safe characters to avoid shell escaping issues
        var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var passphrase = new StringBuilder();
        
        for (int i = 0; i < length; i++)
        {
            passphrase.Append(chars[random.Next(chars.Length)]);
        }
        
        return passphrase.ToString();
    }
} 