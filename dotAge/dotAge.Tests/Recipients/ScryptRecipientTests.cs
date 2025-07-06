using System;
using System.Text;
using System.Threading.Tasks;
using DotAge.Core.Crypto;
using DotAge.Core.Format;
using DotAge.Core.Recipients;
using Xunit;

namespace DotAge.Tests.Recipients
{
    public class ScryptRecipientTests
    {
        [Fact]
        public void Constructor_ShouldCreateValidRecipient_WhenGivenPassphrase()
        {
            // Arrange
            var passphrase = "password";

            // Act
            var recipient = new ScryptRecipient(passphrase);

            // Assert
            Assert.Equal("scrypt", recipient.Type);
        }

        [Fact]
        public void Constructor_ShouldCreateValidRecipient_WhenGivenPassphraseAndSalt()
        {
            // Arrange
            var passphrase = "password";
            var salt = Scrypt.GenerateSalt();

            // Act
            var recipient = new ScryptRecipient(passphrase, salt);

            // Assert
            Assert.Equal("scrypt", recipient.Type);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullPassphrase()
        {
            // Arrange
            string passphrase = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ScryptRecipient(passphrase));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenEmptyPassphrase()
        {
            // Arrange
            var passphrase = "";

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ScryptRecipient(passphrase));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenNullSalt()
        {
            // Arrange
            var passphrase = "password";
            byte[] salt = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ScryptRecipient(passphrase, salt));
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenGivenEmptySalt()
        {
            // Arrange
            var passphrase = "password";
            var salt = new byte[0];

            // Act & Assert
            Assert.Throws<ArgumentException>(() => new ScryptRecipient(passphrase, salt));
        }

        [Fact]
        public void CreateStanza_ShouldReturnValidStanza()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var stanza = recipient.CreateStanza(fileKey);

            // Assert
            Assert.NotNull(stanza);
            Assert.Equal("scrypt", stanza.Type);
            Assert.Single(stanza.Arguments);
            Assert.Single(stanza.Body);
        }

        [Fact]
        public void CreateStanza_ShouldThrowException_WhenGivenNullFileKey()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            byte[] fileKey = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.CreateStanza(fileKey));
        }

        [Fact]
        public void CreateStanza_ShouldThrowException_WhenGivenInvalidFileKeySize()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.CreateStanza(fileKey));
        }

        [Fact]
        public void UnwrapKey_ShouldReturnOriginalFileKey_WhenGivenCorrectPassphrase()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = recipient.CreateStanza(fileKey);

            // Act
            var unwrappedKey = recipient.UnwrapKey(stanza);

            // Assert
            Assert.Equal(fileKey, unwrappedKey);
        }

        [Fact]
        public void UnwrapKey_ShouldReturnNull_WhenGivenIncorrectPassphrase()
        {
            // Arrange
            var correctPassphrase = "password";
            var incorrectPassphrase = "wrong-password";
            var recipient1 = new ScryptRecipient(correctPassphrase);
            var recipient2 = new ScryptRecipient(incorrectPassphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = recipient1.CreateStanza(fileKey);

            // Act
            var unwrappedKey = recipient2.UnwrapKey(stanza);

            // Assert
            Assert.Null(unwrappedKey);
        }

        [Fact]
        public void UnwrapKey_ShouldThrowException_WhenGivenNullStanza()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => recipient.UnwrapKey(null));
        }

        [Fact]
        public void UnwrapKey_ShouldThrowException_WhenGivenStanzaWithWrongType()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var stanza = new Stanza("X25519");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => recipient.UnwrapKey(stanza));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldReturnValidStanza()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var stanza = await recipient.CreateStanzaAsync(fileKey);

            // Assert
            Assert.NotNull(stanza);
            Assert.Equal("scrypt", stanza.Type);
            Assert.Single(stanza.Arguments);
            Assert.Single(stanza.Body);
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldThrowException_WhenGivenNullFileKey()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            byte[] fileKey = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.CreateStanzaAsync(fileKey));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldThrowException_WhenGivenInvalidFileKeySize()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = new byte[] { 0x01, 0x02, 0x03 }; // Not 32 bytes

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.CreateStanzaAsync(fileKey));
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldReturnOriginalFileKey_WhenGivenCorrectPassphrase()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = await recipient.CreateStanzaAsync(fileKey);

            // Act
            var unwrappedKey = await recipient.UnwrapKeyAsync(stanza);

            // Assert
            Assert.Equal(fileKey, unwrappedKey);
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldReturnNull_WhenGivenIncorrectPassphrase()
        {
            // Arrange
            var correctPassphrase = "password";
            var incorrectPassphrase = "wrong-password";
            var recipient1 = new ScryptRecipient(correctPassphrase);
            var recipient2 = new ScryptRecipient(incorrectPassphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();
            var stanza = await recipient1.CreateStanzaAsync(fileKey);

            // Act
            var unwrappedKey = await recipient2.UnwrapKeyAsync(stanza);

            // Assert
            Assert.Null(unwrappedKey);
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldThrowException_WhenGivenNullStanza()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await recipient.UnwrapKeyAsync(null));
        }

        [Fact]
        public async Task UnwrapKeyAsync_ShouldThrowException_WhenGivenStanzaWithWrongType()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var stanza = new Stanza("X25519");

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await recipient.UnwrapKeyAsync(stanza));
        }

        [Fact]
        public async Task CreateStanzaAsync_ShouldProduceSameResultsAsSync()
        {
            // Arrange
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
            var fileKey = ChaCha20Poly1305.GenerateKey();

            // Act
            var syncStanza = recipient.CreateStanza(fileKey);
            var asyncStanza = await recipient.CreateStanzaAsync(fileKey);

            // We can't directly compare the stanzas because they use random salts
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
            var passphrase = "password";
            var recipient = new ScryptRecipient(passphrase);
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
