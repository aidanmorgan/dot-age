using System;
using System.IO;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using Xunit;

namespace DotAge.Tests.Integration
{
    public class AgeKeygenIntegrationTests
    {

        [Fact]
        public void EncryptWithDotAge_DecryptWithDotAge_UsingAgeKeygenGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age-keygen command is not available
            if (!builder.IsAgeKeygenExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithTextContent("Hello, World! This is a test using age-keygen-generated keys.")
                .GenerateKeys()
                .ConfigureEncryption()
                .ConfigureDecryption()
                .EncryptWithDotAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_UsingAgeKeygenGeneratedKeys_TextData_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Create a larger text content
            var originalText = "Hello, World! This is a test using age-keygen-generated keys.\n";
            for (int i = 0; i < 100; i++)
            {
                originalText += $"Line {i}: The quick brown fox jumps over the lazy dog.\n";
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithTextContent(originalText)
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_UsingAgeKeygenGeneratedKeys_TextData_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Create a larger text content
            var originalText = "Hello, World! This is a test using age-keygen-generated keys.\n";
            for (int i = 0; i < 100; i++)
            {
                originalText += $"Line {i}: The quick brown fox jumps over the lazy dog.\n";
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithTextContent(originalText)
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

        [Theory]
        [InlineData(1024)]        // 1 KB
        [InlineData(1024 * 10)]   // 10 KB
        [InlineData(1024 * 100)]  // 100 KB
        public void EncryptWithDotAge_DecryptWithAge_BinaryData_UsingAgeKeygenGeneratedKeys_ShouldWork(int fileSize)
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
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
        public void EncryptWithAge_DecryptWithDotAge_BinaryData_UsingAgeKeygenGeneratedKeys_ShouldWork(int fileSize)
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithRandomBinaryContent(fileSize)
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedBinaryContentMatches();
        }

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_SpecialCharacters_UsingAgeKeygenGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithSpecialCharactersContent()
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_SpecialCharacters_UsingAgeKeygenGeneratedKeys_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithSpecialCharactersContent()
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

    }
}
