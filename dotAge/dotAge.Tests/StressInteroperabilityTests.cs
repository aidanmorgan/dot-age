using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);
    private static readonly DotAge.Cli.Program _cli = new DotAge.Cli.Program();
    private static readonly DotAge.KeyGen.Program _keyGen = new DotAge.KeyGen.Program();

    private const int DefaultStressTestCount = 10000;

    private static readonly IList<int> PlaintextDataSizes = new List<int>()
    {
        0,      // Empty file
        1,      // Single byte
        16,     // AES block
        32,     // Two AES blocks
        64,     // ChaCha20 block
        128,    // Small text
        256,    // Short document
        512,    // Medium text
        1024,   // 1KB
        4096,   // 4KB
        8192,   // 8KB
        16384,  // 16KB
        65536,  // 64KB
        262144, // 256KB
        1048576 // 1MB
    };
    
    private readonly ILogger _logger;
    private readonly string _tempDir;
    private readonly Random _random;

    public StressInteroperabilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("stress-interop-tests");
        _random = new Random(Environment.TickCount + Thread.CurrentThread.ManagedThreadId);

        _logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
    }

    public void Dispose()
    {
    }

    [Fact(DisplayName = "Stress Test: Randomized interoperability tests")]
    public async Task StressTest_RandomizedInteroperabilityTests()
    {
        using var cts = new CancellationTokenSource(TestTimeout);
        var runStressTests = Environment.GetEnvironmentVariable("RUN_STRESS_TESTS");
        if (string.IsNullOrEmpty(runStressTests) || runStressTests.ToLower() != "true")
        {
            _logger.LogInformation("Skipping stress tests. Set RUN_STRESS_TESTS=true to run them.");
            return;
        }

        _logger.LogInformation("Starting stress test with 5000 randomized interoperability tests");
        
        for (int i = 0; i < DefaultStressTestCount; i++)
        {
            var dataSize = PlaintextDataSizes[_random.Next(PlaintextDataSizes.Count)];
            dataSize += _random.Next(-16, 16);

            if (dataSize < 0)
            {
                dataSize = _random.Next(1, 1048576);
            }
            
            var testData = GenerateRandomTestData(dataSize);
            var passphrase = GenerateRandomPassphrase(i);

            await RunRandomizedTest(i, testData, passphrase);
        }
    }
    

    private async Task RunRandomizedTest(int testNumber, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogTrace("=== TEST {TestNumber} START ===", testNumber);
        logger.LogTrace("Test data length: {DataLength} bytes", testData.Length);
        logger.LogTrace("Test data (first 32 bytes): {DataPrefix}", BitConverter.ToString(testData.Take(32).ToArray()));
        logger.LogTrace("Passphrase length: {PassphraseLength} characters", passphrase.Length);
        logger.LogTrace("Passphrase (first 8 chars): {PassphrasePrefix}", passphrase.Substring(0, Math.Min(8, passphrase.Length)));
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testDir = Path.Combine(_tempDir, $"test_{testNumber}");
        Directory.CreateDirectory(testDir);
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        await File.WriteAllBytesAsync(plaintextFile, testData, cts.Token);
        logger.LogTrace("Wrote plaintext file: {Path}, length: {Length}, first 32 bytes: {Prefix}", plaintextFile, testData.Length, BitConverter.ToString(testData.Take(32).ToArray()));

        var testMethods = new (string Name, Func<Task> Method)[]
        {
            ("Key-based: DotAge -> Age -> Rage", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedDotAgeToAgeToRage(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Age -> DotAge -> Rage", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedAgeToDotAgeToRage(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Rage -> DotAge -> Age", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedRageToDotAgeToAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: DotAge -> Rage -> Age", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedDotAgeToRageToAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Age -> Rage -> DotAge", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedAgeToRageToDotAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Key-based: Rage -> Age -> DotAge", async () => {
                var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
                var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
                var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
                
                await GenerateAgeKey(ageKeyFile);
                await GenerateRageKey(rageKeyFile);
                await GenerateDotAgeKey(dotageKeyFile);
                
                await TestKeyBasedRageToAgeToDotAge(testDir, testData, ageKeyFile, rageKeyFile, dotageKeyFile);
            }),
            ("Passphrase-based: DotAge -> Age -> Rage", async () => await TestPassphraseBasedDotAgeToAgeToRage(testDir, testData, passphrase)),
            ("Passphrase-based: Age -> DotAge -> Rage", async () => await TestPassphraseBasedAgeToDotAgeToRage(testDir, testData, passphrase)),
            ("Passphrase-based: Rage -> DotAge -> Age", async () => await TestPassphraseBasedRageToDotAgeToAge(testDir, testData, passphrase)),
            ("Passphrase-based: DotAge -> Rage -> Age", async () => await TestPassphraseBasedDotAgeToRageToAge(testDir, testData, passphrase)),
            ("Passphrase-based: Age -> Rage -> DotAge", async () => await TestPassphraseBasedAgeToRageToDotAge(testDir, testData, passphrase)),
            ("Passphrase-based: Rage -> Age -> DotAge", async () => await TestPassphraseBasedRageToAgeToDotAge(testDir, testData, passphrase))
        };

        var selectedTest = testMethods[_random.Next(testMethods.Length)];
        
        logger.LogInformation("Test {TestNumber}: Running permutation: {Permutation}", testNumber, selectedTest.Name);
        
        try
        {
            await selectedTest.Method();
            TestUtils.SafeDeleteDirectory(testDir);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Test permutation {Permutation} failed. Test directory preserved for analysis: {TestDir}", selectedTest.Name, testDir);
            
            Assert.Fail();
            throw;
        }
        finally
        {
            logger.LogTrace("=== TEST {TestNumber} END ===", testNumber);
        }
    }

    private async Task GenerateAgeKey(string keyFile)
    {
        await TestUtils.RunCommandAsync("age-keygen", $"-o {keyFile}");
        _logger.LogTrace("Generated age key file {KeyFile} contents:\n{Contents}", keyFile, File.ReadAllText(keyFile));
    }

    private async Task GenerateRageKey(string keyFile)
    {
        await TestUtils.RunCommandAsync("rage-keygen", $"-o {keyFile}");
        _logger.LogTrace("Generated rage key file {KeyFile} contents:\n{Contents}", keyFile, File.ReadAllText(keyFile));
    }

    private async Task GenerateDotAgeKey(string keyFile)
    {
        var keyContent = _keyGen.GenerateKeyPairContent();
        await File.WriteAllTextAsync(keyFile, keyContent);
        _logger.LogTrace("Generated dotage key file {KeyFile} contents:\n{Contents}", keyFile, keyContent);
    }

    private async Task TestKeyBasedDotAgeToAgeToRage(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: DotAge -> Age -> Rage ===");
        logger.LogTrace("=== {MethodName} START ===", nameof(TestKeyBasedDotAgeToAgeToRage));
        logger.LogTrace("Parameters: testDir={TestDir}, testDataLength={TestDataLength}, ageKeyFile={AgeKeyFile}, rageKeyFile={RageKeyFile}, dotageKeyFile={DotAgeKeyFile}", testDir, testData.Length, ageKeyFile, rageKeyFile, dotageKeyFile);
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = await Task.Run(() => new Age(), cts.Token);
        var agePublicKey = KeyFileUtils.DecodeAgePublicKey(agePublicKeyLine);
        await Task.Run(() => age.AddRecipient(new X25519Recipient(agePublicKey)), cts.Token);
        var dotageCiphertext = await Task.Run(() => age.Encrypt(testData), cts.Token);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext, cts.Token);
        logger.LogTrace("Wrote dotage encrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageEncrypted, dotageCiphertext.Length, BitConverter.ToString(dotageCiphertext.Take(32).ToArray()));

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {dotageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);

        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {ragePublicKeyLine} -o {ageReEncrypted} {ageDecrypted}");

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecrypted} {ageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);
        logger.LogTrace("=== {MethodName} END ===", nameof(TestKeyBasedDotAgeToAgeToRage));
    }

    private async Task TestKeyBasedAgeToDotAgeToRage(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: Age -> DotAge -> Rage ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {ragePublicKeyLine} -o {ageEncrypted} {plaintextFile}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (ragePrivateKeyBytes, ragePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(rageKeyFile);
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddIdentity(new X25519Recipient(ragePrivateKeyBytes, ragePublicKeyBytes)), cts.Token);
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(ageCiphertext), cts.Token);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData, cts.Token);

        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = await Task.Run(() => new Age(), cts.Token);
        var dotagePublicKey = KeyFileUtils.DecodeAgePublicKey(dotagePublicKeyLine);
        await Task.Run(() => dotageAge.AddRecipient(new X25519Recipient(dotagePublicKey)), cts.Token);
        var dotageReCiphertext = await Task.Run(() => dotageAge.Encrypt(dotageDecryptedData), cts.Token);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext, cts.Token);

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        await TestUtils.RunCommandAsync("rage", $"-d -i {dotageKeyFile} -o {rageDecrypted} {dotageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestKeyBasedRageToDotAgeToAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: Rage -> DotAge -> Age ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {dotagePublicKeyLine} -o {rageEncrypted} {plaintextFile}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddIdentity(new X25519Recipient(dotagePrivateKeyBytes, dotagePublicKeyBytes)), cts.Token);
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(rageCiphertext), cts.Token);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData, cts.Token);

        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = await Task.Run(() => new Age(), cts.Token);
        var agePublicKey = KeyFileUtils.DecodeAgePublicKey(agePublicKeyLine);
        await Task.Run(() => dotageAge.AddRecipient(new X25519Recipient(agePublicKey)), cts.Token);
        var dotageReCiphertext = await Task.Run(() => dotageAge.Encrypt(dotageDecryptedData), cts.Token);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext, cts.Token);

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {dotageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestKeyBasedDotAgeToRageToAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: DotAge -> Rage -> Age ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = await Task.Run(() => new Age(), cts.Token);
        var ragePublicKey = KeyFileUtils.DecodeAgePublicKey(ragePublicKeyLine);
        await Task.Run(() => age.AddRecipient(new X25519Recipient(ragePublicKey)), cts.Token);
        var dotageCiphertext = await Task.Run(() => age.Encrypt(testData), cts.Token);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext, cts.Token);
        logger.LogTrace("Wrote dotage encrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageEncrypted, dotageCiphertext.Length, BitConverter.ToString(dotageCiphertext.Take(32).ToArray()));

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecrypted} {dotageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);

        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageReEncrypted} {rageDecrypted}");

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {rageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestKeyBasedAgeToRageToDotAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: Age -> Rage -> DotAge ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {ragePublicKeyLine} -o {ageEncrypted} {plaintextFile}");

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("rage", $"-d -i {rageKeyFile} -o {rageDecrypted} {ageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);

        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageReEncrypted} {rageDecrypted}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (agePrivateKeyBytes, agePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(ageKeyFile);
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddIdentity(new X25519Recipient(agePrivateKeyBytes, agePublicKeyBytes)), cts.Token);
        var rageReCiphertext = await File.ReadAllBytesAsync(rageReEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(rageReCiphertext), cts.Token);
        logger.LogTrace("Read dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, dotageDecryptedData);
    }

    private async Task TestKeyBasedRageToAgeToDotAge(string testDir, byte[] testData, string ageKeyFile, string rageKeyFile, string dotageKeyFile)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Key-based: Rage -> Age -> DotAge ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("rage", $"-e -r {agePublicKeyLine} -o {rageEncrypted} {plaintextFile}");

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandAsync("age", $"-d -i {ageKeyFile} -o {ageDecrypted} {rageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);

        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandAsync("age", $"-e -r {dotagePublicKeyLine} -o {ageReEncrypted} {ageDecrypted}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var (dotagePrivateKeyBytes, dotagePublicKeyBytes) = KeyFileUtils.ParseKeyFileAsBytes(dotageKeyFile);
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddIdentity(new X25519Recipient(dotagePrivateKeyBytes, dotagePublicKeyBytes)), cts.Token);
        var ageReCiphertext = await File.ReadAllBytesAsync(ageReEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(ageReCiphertext), cts.Token);
        logger.LogTrace("Read dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, dotageDecryptedData);
    }

    private async Task TestPassphraseBasedDotAgeToAgeToRage(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: DotAge -> Age -> Rage ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var dotageCiphertext = await Task.Run(() => age.Encrypt(testData), cts.Token);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext, cts.Token);
        logger.LogTrace("Wrote dotage encrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageEncrypted, dotageCiphertext.Length, BitConverter.ToString(dotageCiphertext.Take(32).ToArray()));

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {dotageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);

        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageReEncrypted} {ageDecrypted}");

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {ageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestPassphraseBasedAgeToDotAgeToRage(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: Age -> DotAge -> Rage ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageEncrypted} {plaintextFile}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => age.AddIdentity(new ScryptIdentity(passphrase)), cts.Token);
        var ageCiphertext = await File.ReadAllBytesAsync(ageEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(ageCiphertext), cts.Token);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData, cts.Token);
        logger.LogTrace("Wrote dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));

        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => dotageAge.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var dotageReCiphertext = await Task.Run(() => dotageAge.Encrypt(dotageDecryptedData), cts.Token);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext, cts.Token);

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {dotageReEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);
    }

    private async Task TestPassphraseBasedRageToDotAgeToAge(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: Rage -> DotAge -> Age ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageEncrypted} {plaintextFile}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = await Task.Run(() => new Age(), cts.Token);
        age.AddIdentity(new ScryptIdentity(passphrase));
        var rageCiphertext = await File.ReadAllBytesAsync(rageEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(rageCiphertext), cts.Token);
        Assert.Equal(testData, dotageDecryptedData);
        await File.WriteAllBytesAsync(dotageDecrypted, dotageDecryptedData, cts.Token);
        logger.LogTrace("Wrote dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));

        var dotageReEncrypted = Path.Combine(testDir, $"dotage_re_encrypted_{testNumber}.age");
        var dotageAge = await Task.Run(() => new Age(), cts.Token);
        await Task.Run(() => dotageAge.AddRecipient(new ScryptRecipient(passphrase)), cts.Token);
        var dotageReCiphertext = await Task.Run(() => dotageAge.Encrypt(dotageDecryptedData), cts.Token);
        await File.WriteAllBytesAsync(dotageReEncrypted, dotageReCiphertext, cts.Token);

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {dotageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestPassphraseBasedDotAgeToRageToAge(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: DotAge -> Rage -> Age ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var age = await Task.Run(() => new Age(), cts.Token);
        age.AddRecipient(new ScryptRecipient(passphrase));
        var dotageCiphertext = await Task.Run(() => age.Encrypt(testData), cts.Token);
        await File.WriteAllBytesAsync(dotageEncrypted, dotageCiphertext, cts.Token);
        logger.LogTrace("Wrote dotage encrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageEncrypted, dotageCiphertext.Length, BitConverter.ToString(dotageCiphertext.Take(32).ToArray()));

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {dotageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);

        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageReEncrypted} {rageDecrypted}");

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {rageReEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);
    }

    private async Task TestPassphraseBasedAgeToRageToDotAge(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: Age -> Rage -> DotAge ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageEncrypted} {plaintextFile}");

        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-d -o {rageDecrypted} {ageEncrypted}");
        var rageDecryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        logger.LogTrace("Read rage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", rageDecrypted, rageDecryptedData.Length, BitConverter.ToString(rageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, rageDecryptedData);

        var rageReEncrypted = Path.Combine(testDir, $"rage_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageReEncrypted} {rageDecrypted}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = await Task.Run(() => new Age(), cts.Token);
        age.AddIdentity(new ScryptIdentity(passphrase));
        var rageReCiphertext = await File.ReadAllBytesAsync(rageReEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(rageReCiphertext), cts.Token);
        logger.LogTrace("Read dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, dotageDecryptedData);
    }

    private async Task TestPassphraseBasedRageToAgeToDotAge(string testDir, byte[] testData, string passphrase)
    {
        var logger = DotAge.Core.Logging.LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("=== PERMUTATION: Passphrase-based: Rage -> Age -> DotAge ===");
        
        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();
        
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("rage", passphrase, $"-e -p -o {rageEncrypted} {plaintextFile}");

        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {rageEncrypted}");
        var ageDecryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        logger.LogTrace("Read age decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", ageDecrypted, ageDecryptedData.Length, BitConverter.ToString(ageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, ageDecryptedData);

        var ageReEncrypted = Path.Combine(testDir, $"age_re_encrypted_{testNumber}.age");
        await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageReEncrypted} {ageDecrypted}");

        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var age = await Task.Run(() => new Age(), cts.Token);
        age.AddIdentity(new ScryptIdentity(passphrase));
        var ageReCiphertext = await File.ReadAllBytesAsync(ageReEncrypted, cts.Token);
        var dotageDecryptedData = await Task.Run(() => age.Decrypt(ageReCiphertext), cts.Token);
        logger.LogTrace("Read dotage decrypted file: {Path}, length: {Length}, first 32 bytes: {Prefix}", dotageDecrypted, dotageDecryptedData.Length, BitConverter.ToString(dotageDecryptedData.Take(32).ToArray()));
        Assert.Equal(testData, dotageDecryptedData);
    }
    
    private byte[] GenerateRandomTestData(int dataSize)
    {
        if (_random.Next(2) == 0)
        {
            var data = new byte[dataSize];
            _random.NextBytes(data);
            return data;
        }
        else
        {
            var textBuilder = new StringBuilder();

            var lines = _random.Next(1, 20);
            for (int line = 0; line < lines; line++)
            {
                var words = _random.Next(1, 20);
                for (int word = 0; word < words; word++)
                {
                    var wordLength = _random.Next(1, 15);
                    for (int charIndex = 0; charIndex < wordLength; charIndex++)
                    {
                        var asciiChar = (char)_random.Next(32, 127);
                        textBuilder.Append(asciiChar);
                    }

                    if (word < words - 1) textBuilder.Append(' ');
                }

                if (line < lines - 1) textBuilder.AppendLine();
            }

            var text = textBuilder.ToString();
            var data = Encoding.UTF8.GetBytes(text);

            if (data.Length > dataSize)
            {
                var truncatedData = new byte[dataSize];
                Array.Copy(data, truncatedData, dataSize);
                return truncatedData;
            }
            
            return data;
        }
    }

    private string GenerateRandomPassphrase(int seed)
    {
        var rng = new Random(seed);
        var words = new List<string>(10);

        for (int i = 0; i < 10; i++)
        {
            words.Add(Bip39Wordlist.GetRandomWord(rng));
        }

        return string.Join("-", words);
    }
} 