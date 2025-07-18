using DotAge.Core.Utils;

namespace DotAge.Tests;

/// <summary>
///     Tests for input validation and error handling.
/// </summary>
public class ValidationTests
{
    [Fact]
    public void ValidationUtils_ModernValidation_Works()
    {
        // Test ValidateFileKey with modern validation
        var validKey = new byte[16];
        ValidationUtils.ValidateFileKey(validKey); // Should not throw

        // Test null validation
        Assert.Throws<ArgumentNullException>(() => ValidationUtils.ValidateFileKey(null));

        // Test string validation
        ValidationUtils.ValidateStringNotNullOrEmpty("valid-string"); // Should not throw
        Assert.Throws<ArgumentException>(() => ValidationUtils.ValidateStringNotNullOrEmpty(""));
        Assert.Throws<ArgumentNullException>(() => ValidationUtils.ValidateStringNotNullOrEmpty(null));

        // Test whitespace validation
        ValidationUtils.ValidateStringNotNullOrWhiteSpace("valid-string"); // Should not throw
        Assert.Throws<ArgumentException>(() => ValidationUtils.ValidateStringNotNullOrWhiteSpace("   "));
        Assert.Throws<ArgumentException>(() => ValidationUtils.ValidateStringNotNullOrWhiteSpace(""));
        Assert.Throws<ArgumentNullException>(() => ValidationUtils.ValidateStringNotNullOrWhiteSpace(null));
    }
}