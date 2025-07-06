using System;
using System.Text;
using DotAge.Core.Crypto;
using Xunit;

namespace DotAge.Tests.Crypto
{
    public class ChaCha20Poly1305Tests
    {
        [Fact]
        public void GenerateKey_ShouldReturnValidKey()
        {
            // Act
            var key = ChaCha20Poly1305.GenerateKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(ChaCha20Poly1305.KeySize, key.Length);
        }

        [Fact]
        public void GenerateNonce_ShouldReturnValidNonce()
        {
            // Act
            var nonce = ChaCha20Poly1305.GenerateNonce();

            // Assert
            Assert.NotNull(nonce);
            Assert.Equal(ChaCha20Poly1305.NonceSize, nonce.Length);
        }

        [Fact]
        public void Encrypt_ShouldReturnValidCiphertext()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var nonce = ChaCha20Poly1305.GenerateNonce();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

            // Act
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Assert
            Assert.NotNull(ciphertext);
            Assert.True(ciphertext.Length > plaintext.Length, "Ciphertext should be longer than plaintext");
        }

        [Fact]
        public void Decrypt_ShouldReturnOriginalPlaintext_WhenGivenValidCiphertext()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var nonce = ChaCha20Poly1305.GenerateNonce();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Act
            var decrypted = ChaCha20Poly1305.Decrypt(key, nonce, ciphertext);

            // Assert
            Assert.NotNull(decrypted);
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenGivenInvalidKey()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var invalidKey = ChaCha20Poly1305.GenerateKey();
            var nonce = ChaCha20Poly1305.GenerateNonce();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Act & Assert
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => ChaCha20Poly1305.Decrypt(invalidKey, nonce, ciphertext));
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenGivenInvalidNonce()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var nonce = ChaCha20Poly1305.GenerateNonce();
            var invalidNonce = ChaCha20Poly1305.GenerateNonce();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Act & Assert
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => ChaCha20Poly1305.Decrypt(key, invalidNonce, ciphertext));
        }

        [Fact]
        public void Decrypt_ShouldThrowException_WhenGivenTamperedCiphertext()
        {
            // Arrange
            var key = ChaCha20Poly1305.GenerateKey();
            var nonce = ChaCha20Poly1305.GenerateNonce();
            var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
            var ciphertext = ChaCha20Poly1305.Encrypt(key, nonce, plaintext);

            // Tamper with the ciphertext
            ciphertext[0] ^= 0x01;

            // Act & Assert
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => ChaCha20Poly1305.Decrypt(key, nonce, ciphertext));
        }
    }
}
