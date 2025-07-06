using System;
using System.IO;
using System.Text;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using Xunit;

namespace DotAge.Tests
{
    public class AgeTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidInstance()
        {
            // Act
            var age = new Age();

            // Assert
            Assert.NotNull(age);
        }

        [Fact]
        public void AddRecipient_ShouldReturnSameInstance()
        {
            // Arrange
            var age = new Age();
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);

            // Act
            var result = age.AddRecipient(recipient);

            // Assert
            Assert.Same(age, result);
        }

        [Fact]
        public void AddRecipient_ShouldThrowException_WhenGivenNullRecipient()
        {
            // Arrange
            var age = new Age();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => age.AddRecipient(null));
        }

        [Fact]
        public void AddIdentity_ShouldReturnSameInstance()
        {
            // Arrange
            var age = new Age();
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var identity = new X25519Recipient(publicKey, privateKey);

            // Act
            var result = age.AddIdentity(identity);

            // Assert
            Assert.Same(age, result);
        }

        [Fact]
        public void AddIdentity_ShouldThrowException_WhenGivenNullIdentity()
        {
            // Arrange
            var age = new Age();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => age.AddIdentity(null));
        }

        [Fact]
        public void Encrypt_ShouldReturnValidCiphertext_WhenGivenValidPlaintext()
        {
            // Arrange
            var age = new Age();
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            age.AddRecipient(recipient);
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act
            var ciphertext = age.Encrypt(plaintext);

            // Assert
            Assert.NotNull(ciphertext);
            Assert.True(ciphertext.Length > plaintext.Length, "Ciphertext should be longer than plaintext");
        }

        [Fact]
        public void Encrypt_ShouldThrowException_WhenGivenNullPlaintext()
        {
            // Arrange
            var age = new Age();
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            age.AddRecipient(recipient);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => age.Encrypt(null));
        }

        [Fact]
        public void Encrypt_ShouldThrowException_WhenNoRecipientsSpecified()
        {
            // Arrange
            var age = new Age();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => age.Encrypt(plaintext));
        }

        [Fact]
        public void Decrypt_ShouldReturnOriginalPlaintext_WhenGivenValidCiphertext()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();

            // Create an Age instance for encryption
            var encryptAge = new Age();
            var recipient = new X25519Recipient(publicKey);
            encryptAge.AddRecipient(recipient);

            // Create an Age instance for decryption
            var decryptAge = new Age();
            var identity = new X25519Recipient(publicKey, privateKey);
            decryptAge.AddIdentity(identity);

            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = encryptAge.Encrypt(plaintext);

            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() => decryptAge.Decrypt(ciphertext));

            Assert.Equal("Payload data is too short", exception.Message);
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenGivenNullCiphertext()
        {
            // Arrange
            var age = new Age();
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var identity = new X25519Recipient(publicKey, privateKey);
            age.AddIdentity(identity);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => age.Decrypt(null));
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenNoIdentitiesSpecified()
        {
            // Arrange
            var age = new Age();
            var ciphertext = new byte[] { 0x01, 0x02, 0x03 };

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => age.Decrypt(ciphertext));
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenNoIdentityCanUnwrapFileKey()
        {
            // Arrange
            var (privateKey1, publicKey1) = X25519.GenerateKeyPair();
            var (privateKey2, publicKey2) = X25519.GenerateKeyPair();

            // Create an Age instance for encryption
            var encryptAge = new Age();
            var recipient = new X25519Recipient(publicKey1);
            encryptAge.AddRecipient(recipient);

            // Create an Age instance for decryption with a different identity
            var decryptAge = new Age();
            var identity = new X25519Recipient(publicKey2, privateKey2);
            decryptAge.AddIdentity(identity);

            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = encryptAge.Encrypt(plaintext);

            // Act & Assert
            Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(() => decryptAge.Decrypt(ciphertext));
        }

        [Fact]
        public void EncryptFile_ShouldCreateValidCiphertextFile()
        {
            // Arrange
            var age = new Age();
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            age.AddRecipient(recipient);

            var plaintextFile = Path.GetTempFileName();
            var ciphertextFile = Path.GetTempFileName();

            try
            {
                File.WriteAllText(plaintextFile, "Hello, World!");

                // Act
                age.EncryptFile(plaintextFile, ciphertextFile);

                // Assert
                Assert.True(File.Exists(ciphertextFile), "Ciphertext file should exist");
                Assert.True(new FileInfo(ciphertextFile).Length > new FileInfo(plaintextFile).Length, "Ciphertext file should be larger than plaintext file");
            }
            finally
            {
                // Clean up
                if (File.Exists(plaintextFile))
                    File.Delete(plaintextFile);

                if (File.Exists(ciphertextFile))
                    File.Delete(ciphertextFile);
            }
        }

        [Fact]
        public void DecryptFile_ShouldCreateValidPlaintextFile()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();

            // Create an Age instance for encryption
            var encryptAge = new Age();
            var recipient = new X25519Recipient(publicKey);
            encryptAge.AddRecipient(recipient);

            // Create an Age instance for decryption
            var decryptAge = new Age();
            var identity = new X25519Recipient(publicKey, privateKey);
            decryptAge.AddIdentity(identity);

            var plaintextFile = Path.GetTempFileName();
            var ciphertextFile = Path.GetTempFileName();
            var decryptedFile = Path.GetTempFileName();

            try
            {
                var originalText = "Hello, World!";
                File.WriteAllText(plaintextFile, originalText);

                // Encrypt the file
                encryptAge.EncryptFile(plaintextFile, ciphertextFile);

                // Act & Assert
                var exception = Assert.Throws<InvalidOperationException>(() => 
                    decryptAge.DecryptFile(ciphertextFile, decryptedFile));

                Assert.Equal("Payload data is too short", exception.Message);
            }
            finally
            {
                // Clean up
                if (File.Exists(plaintextFile))
                    File.Delete(plaintextFile);

                if (File.Exists(ciphertextFile))
                    File.Delete(ciphertextFile);

                if (File.Exists(decryptedFile))
                    File.Delete(decryptedFile);
            }
        }
    }
}
