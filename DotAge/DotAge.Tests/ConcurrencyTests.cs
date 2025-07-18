using System.Collections.Concurrent;
using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;

namespace DotAge.Tests;

/// <summary>
///     Tests to verify thread safety and concurrent operation handling in DotAge.
/// </summary>
public class ConcurrencyTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Age_ConcurrentEncryption_ThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const int operationsPerThread = 5;
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var exceptions = new ConcurrentBag<Exception>();
        var results = new ConcurrentBag<(int ThreadId, int OperationId, byte[] Result)>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
        {
            var capturedThreadId = threadId;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    for (var operationId = 0; operationId < operationsPerThread; operationId++)
                    {
                        using var cts = new CancellationTokenSource(TestTimeout);

                        var age = new Age();
                        age.AddRecipient(new X25519Recipient(publicKey));

                        var plaintext =
                            Encoding.UTF8.GetBytes(
                                $"Thread {capturedThreadId}, Operation {operationId}: {Guid.NewGuid()}");
                        var ciphertext = await Task.Run(() => age.Encrypt(plaintext, cts.Token), cts.Token);

                        results.Add((capturedThreadId, operationId, ciphertext));

                        // Brief delay to increase chance of concurrency issues
                        await Task.Delay(1, cts.Token);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));
        }

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount * operationsPerThread, results.Count);

        // Verify all results are valid and different
        var uniqueResults = new HashSet<string>();
        foreach (var (threadId, operationId, result) in results)
        {
            Assert.True(result.Length > 0, $"Empty result for Thread {threadId}, Operation {operationId}");
            var resultString = Convert.ToBase64String(result);
            Assert.True(uniqueResults.Add(resultString),
                $"Duplicate result found for Thread {threadId}, Operation {operationId}");
        }
    }

    [Fact]
    public async Task Age_ConcurrentDecryption_ThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const string testMessage = "This is a test message for concurrent decryption";
        var (privateKey, publicKey) = X25519.GenerateKeyPair();

        // Pre-encrypt the message
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));
        var plaintext = Encoding.UTF8.GetBytes(testMessage);
        var ciphertext = age.Encrypt(plaintext);

        var exceptions = new ConcurrentBag<Exception>();
        var results = new ConcurrentBag<string>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(TestTimeout);

                    var decryptAge = new Age();
                    decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));

                    var decrypted = await Task.Run(() => decryptAge.Decrypt(ciphertext, cts.Token), cts.Token);
                    var decryptedText = Encoding.UTF8.GetString(decrypted);

                    results.Add(decryptedText);

                    // Brief delay to increase chance of concurrency issues
                    await Task.Delay(1, cts.Token);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount, results.Count);
        Assert.All(results, result => Assert.Equal(testMessage, result));
    }

    [Fact]
    public async Task Age_ConcurrentMixedOperations_ThreadSafe()
    {
        // Arrange
        const int threadCount = 8;
        const int operationsPerThread = 3;
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var exceptions = new ConcurrentBag<Exception>();
        var encryptResults = new ConcurrentBag<byte[]>();
        var decryptResults = new ConcurrentBag<string>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
        {
            var capturedThreadId = threadId;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    for (var operationId = 0; operationId < operationsPerThread; operationId++)
                    {
                        using var cts = new CancellationTokenSource(TestTimeout);

                        var encryptAge = new Age();
                        encryptAge.AddRecipient(new X25519Recipient(publicKey));

                        var message = $"Thread {capturedThreadId}, Operation {operationId}: {Guid.NewGuid()}";
                        var plaintext = Encoding.UTF8.GetBytes(message);

                        // Encrypt
                        var ciphertext = await Task.Run(() => encryptAge.Encrypt(plaintext, cts.Token), cts.Token);
                        encryptResults.Add(ciphertext);

                        // Decrypt immediately
                        var decryptAge = new Age();
                        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
                        var decrypted = await Task.Run(() => decryptAge.Decrypt(ciphertext, cts.Token), cts.Token);
                        var decryptedText = Encoding.UTF8.GetString(decrypted);

                        decryptResults.Add(decryptedText);
                        Assert.Equal(message, decryptedText);

                        // Brief delay to increase chance of concurrency issues
                        await Task.Delay(1, cts.Token);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));
        }

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount * operationsPerThread, encryptResults.Count);
        Assert.Equal(threadCount * operationsPerThread, decryptResults.Count);
    }

    [Fact]
    public async Task Age_ConcurrentFileOperations_ThreadSafe()
    {
        // Arrange
        const int threadCount = 5;
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var exceptions = new ConcurrentBag<Exception>();
        var tempDir = TestUtils.CreateTempDirectory("concurrent-file-tests");

        try
        {
            var tasks = new List<Task>();
            for (var threadId = 0; threadId < threadCount; threadId++)
            {
                var capturedThreadId = threadId;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using var cts = new CancellationTokenSource(TestTimeout);

                        var inputFile = Path.Combine(tempDir, $"input_{capturedThreadId}.txt");
                        var encryptedFile = Path.Combine(tempDir, $"encrypted_{capturedThreadId}.age");
                        var decryptedFile = Path.Combine(tempDir, $"decrypted_{capturedThreadId}.txt");

                        var originalContent = $"Thread {capturedThreadId} test content: {Guid.NewGuid()}";
                        await File.WriteAllTextAsync(inputFile, originalContent, cts.Token);

                        // Encrypt file
                        var encryptAge = new Age();
                        encryptAge.AddRecipient(new X25519Recipient(publicKey));
                        await encryptAge.EncryptFileAsync(inputFile, encryptedFile, cts.Token);

                        // Decrypt file
                        var decryptAge = new Age();
                        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
                        await decryptAge.DecryptFileAsync(encryptedFile, decryptedFile, cts.Token);

                        // Verify content
                        var decryptedContent = await File.ReadAllTextAsync(decryptedFile, cts.Token);
                        Assert.Equal(originalContent, decryptedContent);
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                }));
            }

            // Act
            await Task.WhenAll(tasks);

            // Assert
            Assert.Empty(exceptions);
        }
        finally
        {
            TestUtils.SafeDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task Age_ConcurrentCancellation_HandledCorrectly()
    {
        // Arrange
        const int threadCount = 10;
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var cancellationResults = new ConcurrentBag<bool>();
        var successResults = new ConcurrentBag<bool>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
        {
            var capturedThreadId = threadId;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource();

                    var age = new Age();
                    age.AddRecipient(new X25519Recipient(publicKey));

                    // Generate large data to increase chance of cancellation during operation
                    var largeData = RandomUtils.GenerateRandomBytes(1024 * 1024); // 1MB

                    // Cancel after a very short time for some threads
                    if (capturedThreadId % 3 == 0)
                        cts.CancelAfter(1); // Cancel almost immediately
                    else
                        cts.CancelAfter(5000); // Give enough time to complete

                    try
                    {
                        var ciphertext = await Task.Run(() => age.Encrypt(largeData, cts.Token), cts.Token);
                        successResults.Add(true);
                    }
                    catch (OperationCanceledException)
                    {
                        cancellationResults.Add(true);
                    }
                }
                catch (OperationCanceledException)
                {
                    cancellationResults.Add(true);
                }
            }));
        }

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.True(cancellationResults.Count + successResults.Count == threadCount);
        Assert.True(cancellationResults.Count > 0, "Expected some operations to be cancelled");
    }

    [Fact]
    public async Task ChaCha20Poly1305_ConcurrentOperations_ThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const int operationsPerThread = 10;
        var exceptions = new ConcurrentBag<Exception>();
        var results = new ConcurrentBag<bool>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (var operationId = 0; operationId < operationsPerThread; operationId++)
                    {
                        var key = RandomUtils.GenerateRandomBytes(32);
                        var nonce = RandomUtils.GenerateRandomBytes(12);
                        var plaintext = Encoding.UTF8.GetBytes($"Thread {threadId}, Operation {operationId}");

                        var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);
                        var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);

                        var isEqual = plaintext.SequenceEqual(decrypted);
                        results.Add(isEqual);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount * operationsPerThread, results.Count);
        Assert.All(results, Assert.True);
    }

    [Fact]
    public async Task X25519_ConcurrentKeyGeneration_ThreadSafe()
    {
        // Arrange
        const int threadCount = 10;
        const int keysPerThread = 5;
        var exceptions = new ConcurrentBag<Exception>();
        var keyPairs = new ConcurrentBag<(byte[] PrivateKey, byte[] PublicKey)>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (var keyId = 0; keyId < keysPerThread; keyId++)
                    {
                        var (privateKey, publicKey) = X25519.GenerateKeyPair();
                        keyPairs.Add((privateKey, publicKey));

                        // Verify the key pair works
                        var (otherPrivateKey, otherPublicKey) = X25519.GenerateKeyPair();
                        var sharedSecret1 = X25519.KeyAgreement(privateKey, otherPublicKey);
                        var sharedSecret2 = X25519.KeyAgreement(otherPrivateKey, publicKey);

                        Assert.Equal(sharedSecret1, sharedSecret2);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(threadCount * keysPerThread, keyPairs.Count);

        // Verify all keys are unique
        var privateKeySet = new HashSet<string>();
        var publicKeySet = new HashSet<string>();

        foreach (var (privateKey, publicKey) in keyPairs)
        {
            var privateKeyString = Convert.ToBase64String(privateKey);
            var publicKeyString = Convert.ToBase64String(publicKey);

            Assert.True(privateKeySet.Add(privateKeyString), "Duplicate private key generated");
            Assert.True(publicKeySet.Add(publicKeyString), "Duplicate public key generated");
        }
    }

    [Fact]
    public async Task Age_ConcurrentRecipientManagement_ThreadSafe()
    {
        // Arrange
        const int threadCount = 8;
        var exceptions = new ConcurrentBag<Exception>();
        var recipientCounts = new ConcurrentBag<int>();
        var identityCounts = new ConcurrentBag<int>();

        var tasks = new List<Task>();
        for (var threadId = 0; threadId < threadCount; threadId++)
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    var age = new Age();

                    // Add multiple recipients and identities concurrently
                    var addTasks = new List<Task>();

                    for (var i = 0; i < 5; i++)
                        addTasks.Add(Task.Run(() =>
                        {
                            var (privateKey, publicKey) = X25519.GenerateKeyPair();
                            age.AddRecipient(new X25519Recipient(publicKey));
                            age.AddIdentity(new X25519Recipient(privateKey, publicKey));
                        }));

                    Task.WaitAll(addTasks.ToArray());

                    // Read the counts using the immutable collections
                    recipientCounts.Add(age.Recipients.Count);
                    identityCounts.Add(age.Identities.Count);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));

        // Act
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.All(recipientCounts, count => Assert.Equal(5, count));
        Assert.All(identityCounts, count => Assert.Equal(5, count));
    }
}