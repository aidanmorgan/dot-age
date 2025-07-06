using System;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Format;
using Xunit;

namespace DotAge.Tests.Format
{
    public class PayloadTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidPayload_WhenGivenValidKeyAndData()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var data = new byte[] { 0x01, 0x02, 0x03 };

            // Act
            var payload = new Payload(key, data);

            // Assert
            Assert.Equal(key, payload.GetKey());
            Assert.Equal(data, payload.GetData());
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullKey()
        {
            // Arrange
            byte[] key = null;
            var data = new byte[] { 0x01, 0x02, 0x03 };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new Payload(key, data));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenInvalidKeySize()
        {
            // Arrange
            var key = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes
            var data = new byte[] { 0x01, 0x02, 0x03 };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new Payload(key, data));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullData()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            byte[] data = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new Payload(key, data));
        }

        [Fact]
        public void Encrypt_ShouldReturnValidPayload_WhenGivenValidKeyAndPlaintext()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act
            var payload = Payload.Encrypt(key, plaintext);

            // Assert
            Assert.NotNull(payload);
            Assert.Equal(key, payload.GetKey());
            Assert.NotNull(payload.GetData());
            Assert.True(payload.GetData().Length > plaintext.Length, "Encrypted data should be longer than plaintext");
        }

        [Fact]
        public void Encrypt_ShouldThrowException_WhenGivenNullKey()
        {
            // Arrange
            byte[] key = null;
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => Payload.Encrypt(key, plaintext));
        }

        [Fact]
        public void Encrypt_ShouldThrowException_WhenGivenInvalidKeySize()
        {
            // Arrange
            var key = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => Payload.Encrypt(key, plaintext));
        }

        [Fact]
        public void Encrypt_ShouldThrowException_WhenGivenNullPlaintext()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            byte[] plaintext = null;

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => Payload.Encrypt(key, plaintext));
        }

        [Fact]
        public void Decrypt_ShouldReturnOriginalPlaintext_WhenGivenValidPayload()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var payload = Payload.Encrypt(key, plaintext);

            // Act
            var decrypted = payload.Decrypt();

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenGivenInvalidData()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var data = new byte[] { 0x01, 0x02, 0x03 }; // Not valid encrypted data
            var payload = new Payload(key, data);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => payload.Decrypt());
        }
    }
}
