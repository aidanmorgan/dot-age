using System.Text;
using DotAge.Core;
using DotAge.Core.Recipients;

namespace DotAge.Tests;

public class SelfCompatibilityTests
{
    [Fact]
    public void TestSelfEncryptionDecryption()
    {
        // Create age instance
        var age = new Age();

        // Add a recipient (X25519)
        var recipient = X25519Recipient.FromPublicKey("age1pl92rapq4dh6xw8hehsu8zlyuxl5n5tvsamj3knrjfuz37yg843qzw2r73");
        age.AddRecipient(recipient);

        // Add corresponding identity
        var identity =
            X25519Recipient.FromPrivateKey(
                "AGE-SECRET-KEY-10Y4HLW4SRL5GU0VYHZAQAP9UZRS5ZP4CXUDS2LRLUVLKK6QW3A4QJGNA7X");
        age.AddIdentity(identity);

        // Test data
        var testData = Encoding.UTF8.GetBytes("Hello, World! This is a test message.");

        // Encrypt
        var encrypted = age.Encrypt(testData);

        // Decrypt
        var decrypted = age.Decrypt(encrypted);

        // Verify
        Assert.Equal(testData, decrypted);
    }
}