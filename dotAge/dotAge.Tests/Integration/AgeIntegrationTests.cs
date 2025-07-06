using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Collections.Generic;
using DotAge.Core;
using DotAge.Core.Crypto;
using DotAge.Core.Recipients;
using Xunit;
using Xunit.Sdk;

namespace DotAge.Tests.Integration
{
    public class AgeIntegrationTests
    {

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_ShouldWork()
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
                .WithTextContent("Hello, World!")
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_ShouldWork2()
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
                .WithTextContent("Hello, World!")
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_UsingPassphrase_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithPassphrase("secret-passphrase")
                .WithTextContent("Hello, World!")
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_UsingPassphrase_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.IsAgeExecutableAvailable())
            {
                return;
            }

            // Arrange, Act, Assert
            builder
                .WithPassphrase("secret-passphrase")
                .WithTextContent("Hello, World!")
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }




        [Theory]
        [InlineData(1024)]        // 1 KB
        [InlineData(1024 * 10)]   // 10 KB
        [InlineData(1024 * 100)]  // 100 KB
        public void EncryptWithDotAge_DecryptWithAge_BinaryData_ShouldWork(int fileSize)
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
        public void EncryptWithAge_DecryptWithDotAge_BinaryData_ShouldWork2(int fileSize)
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
        public void EncryptWithDotAge_DecryptWithAge_SpecialCharacters_ShouldWork()
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
        public void EncryptWithAge_DecryptWithDotAge_SpecialCharacters_ShouldWork2()
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

        [Fact]
        public void EncryptWithDotAge_DecryptWithAge_JsonData_ShouldWork()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Create JSON content
            var json = @"{
  ""name"": ""DotAge Test"",
  ""version"": ""1.0.0"",
  ""description"": ""Test file for age encryption"",
  ""main"": ""index.js"",
  ""scripts"": {
    ""test"": ""echo \""Error: no test specified\"" && exit 1""
  },
  ""keywords"": [
    ""age"",
    ""encryption"",
    ""test""
  ],
  ""author"": ""Test User"",
  ""license"": ""MIT"",
  ""dependencies"": {
    ""age"": ""^1.0.0"",
    ""DotAge"": ""^1.0.0""
  },
  ""config"": {
    ""port"": 8080,
    ""host"": ""localhost"",
    ""secure"": true,
    ""timeout"": 30000
  },
  ""nested"": {
    ""level1"": {
      ""level2"": {
        ""level3"": {
          ""value"": ""deeply nested value""
        }
      }
    }
  },
  ""array"": [1, 2, 3, 4, 5, ""string"", true, null, {""key"": ""value""}]
}";

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithTextContent(json)
                .GenerateKeys()
                .ConfigureEncryption()
                .EncryptWithDotAge()
                .DecryptWithAge()
                .AssertDecryptedTextContentMatches();
        }

        [Fact]
        public void EncryptWithAge_DecryptWithDotAge_JsonData_ShouldWork2()
        {
            using var builder = new AgeTestBuilder();

            // Skip if age commands are not available
            if (!builder.AreAgeExecutablesAvailable())
            {
                return;
            }

            // Create JSON content
            var json = @"{
  ""name"": ""DotAge Test"",
  ""version"": ""1.0.0"",
  ""description"": ""Test file for age encryption"",
  ""main"": ""index.js"",
  ""scripts"": {
    ""test"": ""echo \""Error: no test specified\"" && exit 1""
  },
  ""keywords"": [
    ""age"",
    ""encryption"",
    ""test""
  ],
  ""author"": ""Test User"",
  ""license"": ""MIT"",
  ""dependencies"": {
    ""age"": ""^1.0.0"",
    ""DotAge"": ""^1.0.0""
  },
  ""config"": {
    ""port"": 8080,
    ""host"": ""localhost"",
    ""secure"": true,
    ""timeout"": 30000
  },
  ""nested"": {
    ""level1"": {
      ""level2"": {
        ""level3"": {
          ""value"": ""deeply nested value""
        }
      }
    }
  },
  ""array"": [1, 2, 3, 4, 5, ""string"", true, null, {""key"": ""value""}]
}";

            // Arrange, Act, Assert
            builder
                .WithAgeKeygenGeneratedKeys()
                .WithTextContent(json)
                .GenerateKeys()
                .ConfigureDecryption()
                .EncryptWithAge()
                .DecryptWithDotAge()
                .AssertDecryptedTextContentMatches();
        }

    }
}
