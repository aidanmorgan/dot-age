using System;
using System.Text;
using System.Threading.Tasks;
using DotAge.Core.Crypto;
using Xunit;

namespace DotAge.Tests.Crypto
{
    public class ScryptTests
    {
        [Fact]
        public void GenerateSalt_ShouldReturnValidSalt()
        {
            // Act
            var salt = Scrypt.GenerateSalt();

            // Assert
            Assert.NotNull(salt);
            Assert.Equal(Scrypt.DefaultSaltSize, salt.Length);
        }

        [Fact]
        public void GenerateSalt_ShouldReturnDifferentSalts_WhenCalledMultipleTimes()
        {
            // Act
            var salt1 = Scrypt.GenerateSalt();
            var salt2 = Scrypt.GenerateSalt();

            // Assert
            Assert.NotEqual(salt1, salt2);
        }

        [Fact]
        public void DeriveKey_ShouldReturnValidKey()
        {
            // Arrange
            var password = "password";
            var salt = Scrypt.GenerateSalt();

            // Act
            var key = Scrypt.DeriveKey(password, salt);

            // Assert
            Assert.NotNull(key);
            Assert.Equal(Scrypt.DefaultKeySize, key.Length);
        }

        [Fact]
        public void DeriveKey_ShouldReturnSameKey_WhenGivenSamePasswordAndSalt()
        {
            // Arrange
            var password = "password";
            var salt = Scrypt.GenerateSalt();

            // Act
            var key1 = Scrypt.DeriveKey(password, salt);
            var key2 = Scrypt.DeriveKey(password, salt);

            // Assert
            Assert.Equal(key1, key2);
        }

        [Fact]
        public void DeriveKey_ShouldReturnDifferentKeys_WhenGivenDifferentPasswords()
        {
            // Arrange
            var password1 = "password1";
            var password2 = "password2";
            var salt = Scrypt.GenerateSalt();

            // Act
            var key1 = Scrypt.DeriveKey(password1, salt);
            var key2 = Scrypt.DeriveKey(password2, salt);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_ShouldReturnDifferentKeys_WhenGivenDifferentSalts()
        {
            // Arrange
            var password = "password";
            var salt1 = Scrypt.GenerateSalt();
            var salt2 = Scrypt.GenerateSalt();

            // Act
            var key1 = Scrypt.DeriveKey(password, salt1);
            var key2 = Scrypt.DeriveKey(password, salt2);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_ShouldThrowException_WhenGivenNullPassword()
        {
            // Arrange
            string password = null;
            var salt = Scrypt.GenerateSalt();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => Scrypt.DeriveKey(password, salt));
        }

        [Fact]
        public void DeriveKey_ShouldThrowException_WhenGivenNullSalt()
        {
            // Arrange
            var password = "password";
            byte[] salt = null;

            // Act & Assert
            Assert.Throws<ArgumentException>(() => Scrypt.DeriveKey(password, salt));
        }

        [Fact]
        public async Task GenerateSaltAsync_ShouldReturnValidSalt()
        {
            // Act
            var salt = await Scrypt.GenerateSaltAsync();

            // Assert
            Assert.NotNull(salt);
            Assert.Equal(Scrypt.DefaultSaltSize, salt.Length);
        }

        [Fact]
        public async Task GenerateSaltAsync_ShouldReturnDifferentSalts_WhenCalledMultipleTimes()
        {
            // Act
            var salt1 = await Scrypt.GenerateSaltAsync();
            var salt2 = await Scrypt.GenerateSaltAsync();

            // Assert
            Assert.NotEqual(salt1, salt2);
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldReturnValidKey()
        {
            // Arrange
            var password = "password";
            var salt = await Scrypt.GenerateSaltAsync();

            // Act
            var key = await Scrypt.DeriveKeyAsync(password, salt);

            // Assert
            Assert.NotNull(key);
            Assert.Equal(Scrypt.DefaultKeySize, key.Length);
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldReturnSameKey_WhenGivenSamePasswordAndSalt()
        {
            // Arrange
            var password = "password";
            var salt = await Scrypt.GenerateSaltAsync();

            // Act
            var key1 = await Scrypt.DeriveKeyAsync(password, salt);
            var key2 = await Scrypt.DeriveKeyAsync(password, salt);

            // Assert
            Assert.Equal(key1, key2);
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldReturnDifferentKeys_WhenGivenDifferentPasswords()
        {
            // Arrange
            var password1 = "password1";
            var password2 = "password2";
            var salt = await Scrypt.GenerateSaltAsync();

            // Act
            var key1 = await Scrypt.DeriveKeyAsync(password1, salt);
            var key2 = await Scrypt.DeriveKeyAsync(password2, salt);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldReturnDifferentKeys_WhenGivenDifferentSalts()
        {
            // Arrange
            var password = "password";
            var salt1 = await Scrypt.GenerateSaltAsync();
            var salt2 = await Scrypt.GenerateSaltAsync();

            // Act
            var key1 = await Scrypt.DeriveKeyAsync(password, salt1);
            var key2 = await Scrypt.DeriveKeyAsync(password, salt2);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldThrowException_WhenGivenNullPassword()
        {
            // Arrange
            string password = null;
            var salt = await Scrypt.GenerateSaltAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await Scrypt.DeriveKeyAsync(password, salt));
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldThrowException_WhenGivenNullSalt()
        {
            // Arrange
            var password = "password";
            byte[] salt = null;

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () => await Scrypt.DeriveKeyAsync(password, salt));
        }

        [Fact]
        public async Task DeriveKeyAsync_ShouldProduceSameResultsAsSync()
        {
            // Arrange
            var password = "password";
            var salt = Scrypt.GenerateSalt();

            // Act
            var syncKey = Scrypt.DeriveKey(password, salt);
            var asyncKey = await Scrypt.DeriveKeyAsync(password, salt);

            // Assert
            Assert.Equal(syncKey, asyncKey);
        }
    }
}
