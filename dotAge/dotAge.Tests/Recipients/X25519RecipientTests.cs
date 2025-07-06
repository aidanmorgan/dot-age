using System;
using System.Text;
using System.Threading.Tasks;
using dotAge.Core.Crypto;
using dotAge.Core.Format;
using dotAge.Core.Recipients;
using Xunit;

namespace dotAge.Tests.Recipients
{
    public class X25519RecipientTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidRecipient_WhenGivenPublicKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();

            // Act
            var recipient = new X25519Recipient(publicKey);

            // Assert
            Assert.Equal("X25519", recipient.Type);
        }

        [Fact]
        public void Constructor_ShouldCreateValidRecipient_WhenGivenPublicAndPrivateKeys()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();

            // Act
            var recipient = new X25519Recipient(publicKey, privateKey);

            // Assert
            Assert.Equal("X25519", recipient.Type);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullPublicKey()
        {
            // Arrange
            byte[] publicKey = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new X25519Recipient(publicKey));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenInvalidPublicKeySize()
        {
            // Arrange
            var publicKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new X25519Recipient(publicKey));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullPrivateKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            byte[] privateKey = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new X25519Recipient(publicKey, privateKey));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenInvalidPrivateKeySize()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var privateKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new X25519Recipient(publicKey, privateKey));
        }

        [Fact]
        public void FromEncodedPublicKey_ShouldReturnValidRecipient_WhenGivenValidEncodedPublicKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var encodedPublicKey = X25519.EncodePublicKey(publicKey);

            // Act
            var recipient = X25519Recipient.FromEncodedPublicKey(encodedPublicKey);

            // Assert
            Assert.NotNull(recipient);
            Assert.Equal("X25519", recipient.Type);
        }

        [Fact]
        public void CreateStanza_ShouldReturnValidStanza()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var stanza = recipient.CreateStanza(fileKey);

            // Assert
            Assert.NotNull(stanza);
            Assert.Equal("X25519", stanza.Type);
            Assert.Equal(1, stanza.Arguments.Count);
            Assert.Equal(1, stanza.Body.Count);
        }

        [Fact]
        public void CreateStanza_ShouldThrowException_WhenGivenNullFileKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            byte[] fileKey = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.CreateStanza(fileKey));
        }

        [Fact]
        public void CreateStanza_ShouldThrowException_WhenGivenInvalidFileKeySize()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.CreateStanza(fileKey));
        }

        [Fact]
        public void UnwrapKey_ShouldReturnNull_WhenRecipientHasNoPrivateKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = recipient.CreateStanza(fileKey);

            // Act
            var unwrappedKey = recipient.UnwrapKey(stanza);

            // Assert
            Assert.Null(unwrappedKey);
        }

        [Fact]
        public void UnwrapKey_ShouldReturnOriginalFileKey_WhenRecipientHasPrivateKey()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = recipient.CreateStanza(fileKey);

            // Act
            var unwrappedKey = recipient.UnwrapKey(stanza);

            // Assert
            Assert.Equal(fileKey, unwrappedKey);
        }

        [Fact]
        public void UnwrapKey_ShouldThrowException_WhenGivenNullStanza()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => recipient.UnwrapKey(null));
        }

        [Fact]
        public void UnwrapKey_ShouldThrowException_WhenGivenStanzaWithWrongType()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var stanza = new Stanza("scrypt");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.UnwrapKey(stanza));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldReturnValidStanza()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var stanza = await recipient.CreateStanzaAsync(fileKey);

            // Assert
            Assert.NotNull(stanza);
            Assert.Equal("X25519", stanza.Type);
            Assert.Equal(1, stanza.Arguments.Count);
            Assert.Equal(1, stanza.Body.Count);
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldThrowException_WhenGivenNullFileKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            byte[] fileKey = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.CreateStanzaAsync(fileKey));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldThrowException_WhenGivenInvalidFileKeySize()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.CreateStanzaAsync(fileKey));
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldReturnNull_WhenRecipientHasNoPrivateKey()
        {
            // Arrange
            var (_, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = await recipient.CreateStanzaAsync(fileKey);

            // Act
            var unwrappedKey = await recipient.UnwrapKeyAsync(stanza);

            // Assert
            Assert.Null(unwrappedKey);
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldReturnOriginalFileKey_WhenRecipientHasPrivateKey()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = await recipient.CreateStanzaAsync(fileKey);

            // Act
            var unwrappedKey = await recipient.UnwrapKeyAsync(stanza);

            // Assert
            Assert.Equal(fileKey, unwrappedKey);
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldThrowException_WhenGivenNullStanza()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await recipient.UnwrapKeyAsync(null));
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldThrowException_WhenGivenStanzaWithWrongType()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var stanza = new Stanza("scrypt");

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.UnwrapKeyAsync(stanza));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldProduceSameResultsAsSync()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var syncStanza = recipient.CreateStanza(fileKey);
            var asyncStanza = await recipient.CreateStanzaAsync(fileKey);

            // We can't directly compare the stanzas because they use random ephemeral keys
            // Instead, we'll verify that both can be unwrapped correctly
            var syncUnwrapped = recipient.UnwrapKey(syncStanza);
            var asyncUnwrapped = await recipient.UnwrapKeyAsync(asyncStanza);

            // Assert
            Assert.Equal(fileKey, syncUnwrapped);
            Assert.Equal(fileKey, asyncUnwrapped);
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldProduceSameResultsAsSync()
        {
            // Arrange
            var (privateKey, publicKey) = X25519.GenerateKeyPair();
            var recipient = new X25519Recipient(publicKey, privateKey);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = recipient.CreateStanza(fileKey);

            // Act
            var syncUnwrapped = recipient.UnwrapKey(stanza);
            var asyncUnwrapped = await recipient.UnwrapKeyAsync(stanza);

            // Assert
            Assert.Equal(syncUnwrapped, asyncUnwrapped);
        }
    }
}
