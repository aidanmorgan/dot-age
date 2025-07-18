using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Exceptions;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using DotAge.Core.Utils;

namespace DotAge.Tests;

/// <summary>
///     Tests for core Age functionality including encryption/decryption, format parsing, and header handling.
/// </summary>
public class CoreTests
{
    [Fact]
    public void Age_EncryptionDecryption_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));

        var plaintext = "Hello, World!";
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var ciphertext = age.Encrypt(plaintextBytes);
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decryptedBytes = decryptAge.Decrypt(ciphertext);

        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        Assert.Equal(plaintext, decryptedText);
    }

    [Fact]
    public void Age_ZeroByteFile_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));
        var emptyData = new byte[0];
        var ciphertext = age.Encrypt(emptyData);
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decrypted = decryptAge.Decrypt(ciphertext);
        Assert.Equal(emptyData, decrypted);
    }

    [Fact]
    public void Age_SingleByteFile_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));
        var data = new byte[] { 0x42 };
        var ciphertext = age.Encrypt(data);
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decrypted = decryptAge.Decrypt(ciphertext);
        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void Age_LargeFile_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));
        var data = RandomUtils.GenerateRandomBytes(1024 * 1024);
        var ciphertext = age.Encrypt(data);
        var decryptAge = new Age();
        decryptAge.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decrypted = decryptAge.Decrypt(ciphertext);
        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void Age_MultipleRecipients_AllCanDecrypt()
    {
        var (key1Private, key1Public) = X25519.GenerateKeyPair();
        var (key2Private, key2Public) = X25519.GenerateKeyPair();
        var (key3Private, key3Public) = X25519.GenerateKeyPair();

        var age = new Age();
        age.AddRecipient(new X25519Recipient(key1Public));
        age.AddRecipient(new X25519Recipient(key2Public));
        age.AddRecipient(new X25519Recipient(key3Public));

        var plaintext = "Hello, World!";
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = age.Encrypt(plaintextBytes);

        // Test that each recipient can decrypt
        var recipients = new[] { key1Private, key2Private, key3Private };
        var publicKeys = new[] { key1Public, key2Public, key3Public };

        for (var i = 0; i < recipients.Length; i++)
        {
            var decryptAge = new Age();
            decryptAge.AddIdentity(new X25519Recipient(recipients[i], publicKeys[i]));

            var decryptedBytes = decryptAge.Decrypt(ciphertext);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            Assert.Equal(plaintext, decryptedText);
        }
    }

    [Fact]
    public void Age_MixedRecipients_Works()
    {
        var (privateKey, publicKey) = X25519.GenerateKeyPair();
        var password = "test-password";

        var age = new Age();
        age.AddRecipient(new X25519Recipient(publicKey));
        age.AddRecipient(new ScryptRecipient(password));

        var plaintext = "Hello, World!";
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = age.Encrypt(plaintextBytes);

        // Test X25519 decryption
        var decryptAge1 = new Age();
        decryptAge1.AddIdentity(new X25519Recipient(privateKey, publicKey));
        var decryptedBytes1 = decryptAge1.Decrypt(ciphertext);
        var decryptedText1 = Encoding.UTF8.GetString(decryptedBytes1);
        Assert.Equal(plaintext, decryptedText1);

        // Test Scrypt decryption
        var decryptAge2 = new Age();
        decryptAge2.AddIdentity(new ScryptIdentity(password));
        var decryptedBytes2 = decryptAge2.Decrypt(ciphertext);
        var decryptedText2 = Encoding.UTF8.GetString(decryptedBytes2);
        Assert.Equal(plaintext, decryptedText2);
    }

    [Fact]
    public void Age_NoRecipients_ThrowsException()
    {
        var age = new Age();
        var inputData = Encoding.UTF8.GetBytes("test");
        Assert.Throws<AgeEncryptionException>(() => age.Encrypt(inputData));
    }

    [Fact]
    public void Age_NoIdentities_ThrowsException()
    {
        var age = new Age();
        var inputData = Encoding.UTF8.GetBytes("test");
        Assert.Throws<AgeDecryptionException>(() => age.Decrypt(inputData));
    }

    [Fact]
    public void Age_ThrowsOnInvalidKey()
    {
        var age = new Age();
        Assert.Throws<AgeKeyException>(() =>
            age.AddRecipient(new X25519Recipient(new byte[31]))); // Wrong key size
    }

    [Fact]
    public void Age_ThrowsOnInvalidFile()
    {
        var age = new Age();
        var invalidData = new byte[] { 0x00, 0x01, 0x02, 0x03 };
        age.AddIdentity(new X25519Recipient(RandomUtils.GenerateRandomBytes(32), RandomUtils.GenerateRandomBytes(32)));
        Assert.Throws<AgeFormatException>(() =>
            age.Decrypt(invalidData));
    }

    [Fact]
    public void Header_Parsing_Works()
    {
        // Valid stanza: 16-byte base64 body ("AAAAAAAAAAAAAAAAAAAAAA==")
        var headerText = "age-encryption.org/v1\n-> X25519 test-arg\nAAAAAAAAAAAAAAAAAAAAAA==\n";
        var header = Header.Decode(headerText);

        Assert.Equal("age-encryption.org/v1", Header.Version);
        Assert.Single(header.Stanzas);
        Assert.Equal("X25519", header.Stanzas[0].Type);
    }

    [Fact]
    public void Header_Serialization_Works()
    {
        var stanza = new Stanza("X25519", new[] { "test-arg" }, Convert.FromBase64String("dGVzdA=="));
        var header = new Header(new[] { stanza });

        var serialized = header.Encode();
        var parsed = Header.Decode(serialized);

        Assert.Equal(Header.Version, Header.Version);
        Assert.Equal(header.Stanzas[0].Type, parsed.Stanzas[0].Type);
    }

    [Fact]
    public void Header_InvalidFormat_ThrowsException()
    {
        Assert.Throws<AgeFormatException>(() => Header.Decode("invalid header"));
        Assert.Throws<AgeFormatException>(() => Header.Decode(""));
    }
}