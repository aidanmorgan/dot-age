using System;
using System.IO;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using Xunit;

namespace DotAge.Tests.Integration
{
    public class DotAgeKeyIntegrationTests
    {

        [Fact]
        public void EncryptWithAge_DecryptWithAge_UsingDotAgeGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age command is not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithTextContent("Hello, World! This is a test using DotAge-generated keys.")
                .GenerateKeys()
                .EncryptWithAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_UsingDotAgeGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age command is not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithTextContent("Hello, World! This is a test using DotAge-generated keys.")
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_UsingDotAgeGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age command is not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithTextContent("Hello, World! This is a test using DotAge-generated keys.")
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithDotAge_DecryptWithDotAge_UsingDotAgeGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithTextContent("Hello, World! This is a test using DotAge-generated keys.")
                .GenerateKeys()
                .ConfigureEncryption()
                .ConfigureDecryption()
                .EncryptWithDotAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

        [Theory]
        [InlineData(1024)]        // 1 KB
        [InlineData(1024 * 10)]   // 10 KB
        [InlineData(1024 * 100)]  // 100 KB
        public void EncryptWithDotAge_DecryptWithAge_BinaryData_UsingDotAgeGeneratedKeys_ShouldWork(int fileSize)
        {
            using var builder = new AgeTestBuilder();

            // Skip if age command is not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithRandomBinaryContent(fileSize)
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedBinaryContentMatches();
        }

        [Theory]
        [InlineData(1024)]        // 1 KB
        [InlineData(1024 * 10)]   // 10 KB
        [InlineData(1024 * 100)]  // 100 KB
        public void EncryptWithAge_DecryptWithDotAge_BinaryData_UsingDotAgeGeneratedKeys_ShouldWork(int fileSize)
        {
            using var builder = new AgeTestBuilder();

            // Skip if age command is not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithDotAgeGeneratedKeys()
                .WithRandomBinaryContent(fileSize)
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedBinaryContentMatches();
        }

    }
}
