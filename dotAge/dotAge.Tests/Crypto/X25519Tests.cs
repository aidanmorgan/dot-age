using System;
using dotAge.Core.Crypto;
using Xunit;

namespace dotAge.Tests.Crypto
{
    public class X25519Tests
    {
        [Fact]
        public void GenerateKeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            var (privateKey, publicKey) = X25519.GenerateKeyPair();

            // Assert
            Assert.NotNull(privateKey);
            Assert.NotNull(publicKey);
            Assert.Equal(X25519.KeySize, privateKey.Length);
            Assert.Equal(X25519.KeySize, publicKey.Length);
        }

        [Fact]
        public void KeyAgreement_ShouldProduceSameSharedSecret_WhenUsingMatchingKeyPairs()
        {
            // Arrange
            var (alicePrivateKey, alicePublicKey) = X25519.GenerateKeyPair();
            var (bobPrivateKey, bobPublicKey) = X25519.GenerateKeyPair();

            // Act
            var aliceSharedSecret = X25519.KeyAgreement(alicePrivateKey, bobPublicKey);
            var bobSharedSecret = X25519.KeyAgreement(bobPrivateKey, alicePublicKey);

            // Assert
            Assert.NotNull(aliceSharedSecret);
            Assert.NotNull(bobSharedSecret);
            Assert.Equal(aliceSharedSecret, bobSharedSecret);
        }

        [Fact]
        public void EncodePublicKey_ShouldReturnValidEncodedKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();

            // Act
            var encodedKey = X25519.EncodePublicKey(publicKey);

            // Assert
            Assert.NotNull(encodedKey);
            Assert.StartsWith(X25519.PublicKeyPrefix, encodedKey);
        }

        [Fact]
        public void DecodePublicKey_ShouldReturnOriginalKey_WhenGivenValidEncodedKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var encodedKey = X25519.EncodePublicKey(publicKey);

            // Act
            var decodedKey = X25519.DecodePublicKey(encodedKey);

            // Assert
            Assert.NotNull(decodedKey);
            Assert.Equal(publicKey, decodedKey);
        }

        [Fact]
        public void EncodePrivateKey_ShouldReturnValidEncodedKey()
        {
            // Arrange
            var (privateKey, _) = X25519.GenerateKeyPair();

            // Act
            var encodedKey = X25519.EncodePrivateKey(privateKey);

            // Assert
            Assert.NotNull(encodedKey);
            Assert.StartsWith(X25519.PrivateKeyPrefix, encodedKey);
        }

        [Fact]
        public void DecodePrivateKey_ShouldReturnOriginalKey_WhenGivenValidEncodedKey()
        {
            // Arrange
            var (privateKey, _) = X25519.GenerateKeyPair();
            var encodedKey = X25519.EncodePrivateKey(privateKey);

            // Act
            var decodedKey = X25519.DecodePrivateKey(encodedKey);

            // Assert
            Assert.NotNull(decodedKey);
            Assert.Equal(privateKey, decodedKey);
        }
    }
}
