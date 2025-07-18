using System.Text;
using DotAge.Cli;
using DotAge.Core.Utils;
using Microsoft.Extensions.Logging;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

namespace DotAge.Integration;

/// <summary>
///     Comprehensive stress tests for interoperability between age, rage, and dotage.
///     Performs 50,000 randomized tests covering 12 specific pairwise permutations between the three implementations.
/// </summary>
public class StressInteroperabilityTests : IDisposable
{
    private const int DefaultStressTestCount = 50000;
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);
    private static readonly Program _cli = new();
    private static readonly KeyGen.Program _keyGen = new();


    private static readonly IList<int> BinaryDataSizes = new List<int>
    {
        1, // Single byte
        16, // AES block
        32, // Two AES blocks
        64, // ChaCha20 block
        128, // Small binary
        256, // Short binary
        512, // Medium binary
        1024, // 1KB
        4096, // 4KB
        8192, // 8KB
        16384, // 16KB
        65536, // 64KB
        262144, // 256KB
        1048576 // 1MB
    };

    private static readonly IList<int> TextDataSizes = new List<int>
    {
        1, // Single character
        16, // Short word
        32, // Short sentence
        64, // Medium sentence
        128, // Short paragraph
        256, // Medium paragraph
        512, // Long paragraph
        1024 // Short document
    };

    private readonly ILogger _logger;
    private readonly Random _random;
    private readonly string _tempDir;

    static StressInteroperabilityTests()
    {
        // Initialize logging from core LoggerFactory
    }

    public StressInteroperabilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("stress-interop-tests");
        _random = new Random(); // Use truly random seed

        _logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
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

        _logger.LogInformation("Starting stress test with {TestCount} randomized interoperability tests",
            DefaultStressTestCount);

        for (var i = 0; i < DefaultStressTestCount; i++)
        {
            // 50% binary data, 50% text data
            var isBinary = _random.Next(2) == 0;

            var dataSize = isBinary
                ? BinaryDataSizes[_random.Next(BinaryDataSizes.Count)]
                : TextDataSizes[_random.Next(TextDataSizes.Count)];

            // Apply jitter: ±25% of the base size, minimum 1 byte
            var jitterRange = Math.Max(1, dataSize / 4);
            dataSize += _random.Next(-jitterRange, jitterRange + 1);
            dataSize = Math.Max(1, dataSize); // Ensure minimum 1 byte

            var testData = GenerateRandomTestData(dataSize, isBinary);
            var passphrase = GenerateRandomPassphrase(i);

            await RunRandomizedTest(i, testData, passphrase, isBinary);
        }
    }


    private async Task RunRandomizedTest(int testNumber, byte[] testData, string passphrase, bool isBinary)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogTrace("=== TEST {TestNumber}/{TotalTests} START ===", testNumber + 1, DefaultStressTestCount);
        logger.LogTrace("Test data length: {DataLength} bytes", testData.Length);
        logger.LogTrace("Test data type: {DataType}", isBinary ? "Binary" : "Text");
        logger.LogTrace("Test data (first 32 bytes): {DataPrefix}", BitConverter.ToString(testData.Take(32).ToArray()));
        logger.LogTrace("Passphrase length: {PassphraseLength} characters", passphrase.Length);
        logger.LogTrace("Passphrase (first 8 chars): {PassphrasePrefix}",
            passphrase.Substring(0, Math.Min(8, passphrase.Length)));

        using var cts = new CancellationTokenSource(TestTimeout);
        var testDir = Path.Combine(_tempDir, $"test_{testNumber}");
        Directory.CreateDirectory(testDir);

        var plaintextFile = Path.Combine(testDir, "plaintext.txt");
        await File.WriteAllBytesAsync(plaintextFile, testData, cts.Token);
        logger.LogTrace("Wrote plaintext file: {Path}, length: {Length}, first 32 bytes: {Prefix}", plaintextFile,
            testData.Length, BitConverter.ToString(testData.Take(32).ToArray()));

        // Define the 12 pairwise test permutations between dotage, age, and rage
        var testMethods = new (string Name, Func<Task> Method)[]
        {
            ("dotage->age (dotage key)", async () => await TestDotAgeEncryptAgeDecryptDotAgeKey(testDir, testData)),
            ("dotage->age (age key)", async () => await TestDotAgeEncryptAgeDecryptAgeKey(testDir, testData)),
            ("dotage->age (passphrase)",
                async () => await TestDotAgeEncryptAgeDecryptPassphrase(testDir, testData, passphrase)),
            ("age->dotage (passphrase)",
                async () => await TestAgeEncryptDotAgeDecryptPassphrase(testDir, testData, passphrase)),
            ("dotage->rage (dotage key)", async () => await TestDotAgeEncryptRageDecryptDotAgeKey(testDir, testData)),
            ("dotage->rage (rage key)", async () => await TestDotAgeEncryptRageDecryptRageKey(testDir, testData)),
            ("dotage->rage (passphrase)",
                async () => await TestDotAgeEncryptRageDecryptPassphrase(testDir, testData, passphrase)),
            ("rage->dotage (passphrase)",
                async () => await TestRageEncryptDotAgeDecryptPassphrase(testDir, testData, passphrase)),
            ("dotage->dotage (dotage key)",
                async () => await TestDotAgeEncryptDotAgeDecryptDotAgeKey(testDir, testData)),
            ("dotage->dotage (age key)", async () => await TestDotAgeEncryptDotAgeDecryptAgeKey(testDir, testData)),
            ("dotage->dotage (rage key)", async () => await TestDotAgeEncryptDotAgeDecryptRageKey(testDir, testData)),
            ("dotage->dotage (passphrase)",
                async () => await TestDotAgeEncryptDotAgeDecryptPassphrase(testDir, testData, passphrase))
        };

        var selectedTest = testMethods[_random.Next(testMethods.Length)];

        logger.LogInformation("Test {TestNumber}/{TotalTests}: Running permutation: {Permutation}", testNumber + 1,
            DefaultStressTestCount, selectedTest.Name);

        try
        {
            await selectedTest.Method();
            TestUtils.SafeDeleteDirectory(testDir);
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Test permutation {Permutation} failed. Test directory preserved for analysis: {TestDir}",
                selectedTest.Name, testDir);

            Assert.Fail();
            throw;
        }
        finally
        {
            logger.LogTrace("=== TEST {TestNumber}/{TotalTests} END ===", testNumber + 1, DefaultStressTestCount);
        }
    }

    // Test 1: dotage->age (dotage key)
    private async Task TestDotAgeEncryptAgeDecryptDotAgeKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate dotage key
        var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
        await GenerateDotAgeKey(dotageKeyFile);

        // Extract public key from dotage key file for encryption
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // Encrypt with dotage using public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {dotagePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with age using private key file
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        var decryptResult = await TestUtils.RunAgeAsync($"-d -i {dotageKeyFile} -o {ageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 2: dotage->age (age key)
    private async Task TestDotAgeEncryptAgeDecryptAgeKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate age key
        var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
        await GenerateAgeKey(ageKeyFile);

        // Extract public key from age key file
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with dotage using age public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {agePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with age
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        var decryptResult = await TestUtils.RunAgeAsync($"-d -i {ageKeyFile} -o {ageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 3: dotage->age (passphrase)
    private async Task TestDotAgeEncryptAgeDecryptPassphrase(string testDir, byte[] testData, string passphrase)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Encrypt with dotage using passphrase
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt --passphrase -o {dotageEncrypted} {plaintextFile}", passphrase);
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with age using passphrase
        var ageDecrypted = Path.Combine(testDir, $"age_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-d -o {ageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(ageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 4: age->dotage (passphrase)
    private async Task TestAgeEncryptDotAgeDecryptPassphrase(string testDir, byte[] testData, string passphrase)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Encrypt with age using passphrase
        var ageEncrypted = Path.Combine(testDir, $"age_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunCommandWithExpectAsync("age", passphrase, $"-e -p -o {ageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt --passphrase -o {dotageDecrypted} {ageEncrypted}", passphrase);
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 5: dotage->rage (dotage key)
    private async Task TestDotAgeEncryptRageDecryptDotAgeKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate dotage key
        var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
        await GenerateDotAgeKey(dotageKeyFile);

        // Extract public key from dotage key file for encryption
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // Encrypt with dotage using public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {dotagePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with rage using private key file
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        var decryptResult = await TestUtils.RunRageAsync($"-d -i {dotageKeyFile} -o {rageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 6: dotage->rage (rage key)
    private async Task TestDotAgeEncryptRageDecryptRageKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate rage key
        var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
        await GenerateRageKey(rageKeyFile);

        // Extract public key from rage key file for encryption
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);

        // Encrypt with dotage using rage public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {ragePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with rage
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        var decryptResult = await TestUtils.RunRageAsync($"-d -i {rageKeyFile} -o {rageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 7: dotage->rage (passphrase)
    private async Task TestDotAgeEncryptRageDecryptPassphrase(string testDir, byte[] testData, string passphrase)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Encrypt with dotage using passphrase
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt --passphrase -o {dotageEncrypted} {plaintextFile}", passphrase);
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with rage using passphrase
        var rageDecrypted = Path.Combine(testDir, $"rage_decrypted_{testNumber}.txt");
        var decryptResult = await TestUtils.RunCommandWithExpectAsync("rage", passphrase,
            $"-d -o {rageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(rageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 8: rage->dotage (passphrase)
    private async Task TestRageEncryptDotAgeDecryptPassphrase(string testDir, byte[] testData, string passphrase)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Encrypt with rage using passphrase
        var rageEncrypted = Path.Combine(testDir, $"rage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult = await TestUtils.RunCommandWithExpectAsync("rage", passphrase,
            $"-e -p -o {rageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt --passphrase -o {dotageDecrypted} {rageEncrypted}", passphrase);
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    private async Task GenerateAgeKey(string keyFile)
    {
        await TestUtils.RunAgeKeyGenAsync($"-o {keyFile}");
        _logger.LogTrace("Generated age key file {KeyFile} contents:\n{Contents}", keyFile, File.ReadAllText(keyFile));
    }

    private async Task GenerateRageKey(string keyFile)
    {
        await TestUtils.RunRageKeyGenAsync($"-o {keyFile}");
        _logger.LogTrace("Generated rage key file {KeyFile} contents:\n{Contents}", keyFile, File.ReadAllText(keyFile));
    }

    private async Task GenerateDotAgeKey(string keyFile)
    {
        var keyContent = _keyGen.GenerateKeyPairContent();
        await File.WriteAllTextAsync(keyFile, keyContent);
        _logger.LogTrace("Generated dotage key file {KeyFile} contents:\n{Contents}", keyFile, keyContent);
    }

    private byte[] GenerateRandomTestData(int dataSize, bool isBinary)
    {
        if (isBinary)
        {
            // Generate random binary data
            var data = new byte[dataSize];
            _random.NextBytes(data);
            return data;
        }
        else
        {
            // Generate random text data
            var textBuilder = new StringBuilder();

            // Generate random text content
            var maxLines = Math.Max(2, dataSize / 64);
            var lines = _random.Next(1, maxLines);
            for (var line = 0; line < lines; line++)
            {
                var maxWords = Math.Max(2, dataSize / 32);
                var words = _random.Next(1, maxWords);
                for (var word = 0; word < words; word++)
                {
                    var maxWordLength = Math.Max(2, Math.Min(15, dataSize / 8));
                    var wordLength = _random.Next(1, maxWordLength);
                    for (var charIndex = 0; charIndex < wordLength; charIndex++)
                    {
                        // Use printable ASCII characters (32-126)
                        var asciiChar = (char)_random.Next(32, 127);
                        textBuilder.Append(asciiChar);
                    }

                    if (word < words - 1) textBuilder.Append(' ');
                }

                if (line < lines - 1) textBuilder.AppendLine();
            }

            var text = textBuilder.ToString();
            var data = Encoding.UTF8.GetBytes(text);

            // If the generated text is larger than requested, truncate it
            if (data.Length > dataSize)
            {
                var truncatedData = new byte[dataSize];
                Array.Copy(data, truncatedData, dataSize);
                return truncatedData;
            }

            // If the generated text is smaller than requested, pad with spaces
            if (data.Length < dataSize)
            {
                var paddedData = new byte[dataSize];
                Array.Copy(data, paddedData, data.Length);
                // Fill remaining space with spaces
                for (var i = data.Length; i < dataSize; i++) paddedData[i] = (byte)' ';
                return paddedData;
            }

            return data;
        }
    }

    private string GenerateRandomPassphrase(int seed)
    {
        var random = new Random(seed);

        // Use Bip39 wordlist with jitter applied to number of words
        // Default age/rage passphrase is typically 12 words, so we'll vary around that
        var baseWordCount = 12;
        var jitterRange = 4; // ±4 words
        var wordCount = baseWordCount + random.Next(-jitterRange, jitterRange + 1);
        wordCount = Math.Max(8, Math.Min(20, wordCount)); // Ensure reasonable bounds (8-20 words)

        var passphrase = new StringBuilder();

        for (var i = 0; i < wordCount; i++)
        {
            if (i > 0) passphrase.Append('-');
            passphrase.Append(Bip39Wordlist.GetRandomWord(random));
        }

        return passphrase.ToString();
    }

    // Test 9: dotage->dotage (dotage key)
    private async Task TestDotAgeEncryptDotAgeDecryptDotAgeKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("Running: dotage->dotage (dotage key)");

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate dotage key
        var dotageKeyFile = Path.Combine(testDir, $"dotage_key_{testNumber}.txt");
        await GenerateDotAgeKey(dotageKeyFile);

        // Extract public key from dotage key file for encryption
        var (_, dotagePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotageKeyFile);

        // Encrypt with dotage using public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {dotagePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using private key file
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt -i {dotageKeyFile} -o {dotageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 10: dotage->dotage (age key)
    private async Task TestDotAgeEncryptDotAgeDecryptAgeKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("Running: dotage->dotage (age key)");

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate age key
        var ageKeyFile = Path.Combine(testDir, $"age_key_{testNumber}.txt");
        await GenerateAgeKey(ageKeyFile);

        // Extract public key from age key file for encryption
        var (_, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeyFile);

        // Encrypt with dotage using age public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {agePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using age private key file
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt -i {ageKeyFile} -o {dotageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 11: dotage->dotage (rage key)
    private async Task TestDotAgeEncryptDotAgeDecryptRageKey(string testDir, byte[] testData)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("Running: dotage->dotage (rage key)");

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Generate rage key
        var rageKeyFile = Path.Combine(testDir, $"rage_key_{testNumber}.txt");
        await GenerateRageKey(rageKeyFile);

        // Extract public key from rage key file for encryption
        var (_, ragePublicKeyLine) = KeyFileUtils.ParseKeyFile(rageKeyFile);

        // Encrypt with dotage using rage public key
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt -r {ragePublicKeyLine} -o {dotageEncrypted} {plaintextFile}");
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using rage private key file
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt -i {rageKeyFile} -o {dotageDecrypted} {dotageEncrypted}");
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }

    // Test 12: dotage->dotage (passphrase)
    private async Task TestDotAgeEncryptDotAgeDecryptPassphrase(string testDir, byte[] testData, string passphrase)
    {
        var logger = LoggerFactory.CreateLogger<StressInteroperabilityTests>();
        logger.LogInformation("Running: dotage->dotage (passphrase)");

        using var cts = new CancellationTokenSource(TestTimeout);
        var testNumber = Path.GetFileName(testDir).Split('_').Last();

        // Encrypt with dotage using passphrase
        var dotageEncrypted = Path.Combine(testDir, $"dotage_encrypted_{testNumber}.age");
        var plaintextFile = Path.Combine(testDir, "plaintext.txt");

        var encryptResult =
            await TestUtils.RunDotAgeAsync($"encrypt --passphrase -o {dotageEncrypted} {plaintextFile}", passphrase);
        Assert.Equal(0, encryptResult.ExitCode);

        // Decrypt with dotage using passphrase
        var dotageDecrypted = Path.Combine(testDir, $"dotage_decrypted_{testNumber}.txt");
        var decryptResult =
            await TestUtils.RunDotAgeAsync($"decrypt --passphrase -o {dotageDecrypted} {dotageEncrypted}", passphrase);
        Assert.Equal(0, decryptResult.ExitCode);

        // Verify decrypted content matches original
        var decryptedData = await File.ReadAllBytesAsync(dotageDecrypted, cts.Token);
        Assert.Equal(testData, decryptedData);
    }
}