using System.CommandLine;
using System.Globalization;
using DotAge.Core.Crypto;
using DotAge.Core.Utils;

namespace DotAge.KeyGen;

/// <summary>
///     Entry point for the age-keygen application.
/// </summary>
public class Program
{
    /// <summary>
    ///     Application entry point.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code.</returns>
    public static async Task<int> Main(string[] args)
    {
        var program = new Program();
        return await program.RunAsync(args);
    }

    /// <summary>
    ///     Runs the application asynchronously with the specified arguments.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code.</returns>
    public async Task<int> RunAsync(string[] args)
    {
        var outputOption = new Option<string>(
            new[] { "-o", "--output" },
            "Write the key pair to the specified file instead of standard output"
        );

        var rootCommand = new RootCommand("Generate a new age key pair")
        {
            outputOption
        };

        rootCommand.SetHandler(async output => await GenerateKeyPairAsync(output), outputOption);

        return await rootCommand.InvokeAsync(args);
    }

    /// <summary>
    ///     Generates a key pair and writes it to the specified output.
    /// </summary>
    /// <param name="output">Output file path, or null for standard output.</param>
    /// <returns>Exit code.</returns>
    public int GenerateKeyPair(string? output)
    {
        try
        {
            var keyOutput = GenerateKeyPairContent();
            WriteOutput(keyOutput, output);
            return 0; // Success
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error generating key pair: {ex.Message}");
            return 1; // Error
        }
    }

    /// <summary>
    ///     Generates a key pair and writes it to the specified output asynchronously.
    /// </summary>
    /// <param name="output">Output file path, or null for standard output.</param>
    /// <returns>Exit code.</returns>
    public async Task<int> GenerateKeyPairAsync(string? output)
    {
        try
        {
            var keyOutput = GenerateKeyPairContent();
            await WriteOutputAsync(keyOutput, output);
            return 0; // Success
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error generating key pair: {ex.Message}");
            return 1; // Error
        }
    }

    /// <summary>
    ///     Writes the key pair to the specified output.
    /// </summary>
    /// <param name="keyOutput">The key pair content.</param>
    /// <param name="output">Output file path, or null for standard output.</param>
    private void WriteOutput(string keyOutput, string? output)
    {
        if (string.IsNullOrEmpty(output))
        {
            // Write to standard output
            Console.WriteLine(keyOutput);
        }
        else
        {
            // Write to the specified file
            File.WriteAllText(output, keyOutput);
            Console.WriteLine($"Key pair written to {output}");

            // Extract and display the public key
            DisplayPublicKey(keyOutput);
        }
    }

    /// <summary>
    ///     Writes the key pair to the specified output asynchronously.
    /// </summary>
    /// <param name="keyOutput">The key pair content.</param>
    /// <param name="output">Output file path, or null for standard output.</param>
    private async Task WriteOutputAsync(string keyOutput, string? output)
    {
        if (string.IsNullOrEmpty(output))
        {
            // Write to standard output
            await Console.Out.WriteLineAsync(keyOutput);
        }
        else
        {
            // Write to the specified file
            await File.WriteAllTextAsync(output, keyOutput);
            await Console.Out.WriteLineAsync($"Key pair written to {output}");

            // Extract and display the public key
            DisplayPublicKey(keyOutput);
        }
    }

    /// <summary>
    ///     Extracts and displays the public key from the key pair content.
    /// </summary>
    /// <param name="keyOutput">The key pair content.</param>
    private void DisplayPublicKey(string keyOutput)
    {
        const string publicKeyPrefix = "# public key: ";

        foreach (var line in keyOutput.Split('\n'))
            if (line.StartsWith(publicKeyPrefix))
            {
                Console.WriteLine($"Public key: {line[publicKeyPrefix.Length..]}");
                break;
            }
    }

    /// <summary>
    ///     Generates a new age key pair and returns the formatted content.
    ///     This method can be called from tests to generate keys programmatically.
    /// </summary>
    /// <returns>The formatted key pair content in age format.</returns>
    public string GenerateKeyPairContent()
    {
        // Generate a new X25519 key pair
        var (privateKey, publicKey) = X25519.GenerateKeyPair();

        // Convert to age format (Bech32)
        var privateKeyAge = KeyFileUtils.EncodeAgeSecretKey(privateKey);
        var publicKeyAge = KeyFileUtils.EncodeAgePublicKey(publicKey);

        // Format the output in standard age format (matching age-keygen exactly)
        return
            $"# created: {DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)}\n# public key: {publicKeyAge}\n{privateKeyAge}\n";
    }

    /// <summary>
    ///     Generates a new age key pair and returns the key components.
    ///     This method can be called from tests to get the raw key data.
    /// </summary>
    /// <returns>A tuple containing (privateKeyBytes, publicKeyBytes, privateKeyAge, publicKeyAge).</returns>
    public (byte[] privateKeyBytes, byte[] publicKeyBytes, string privateKeyAge, string publicKeyAge)
        GenerateKeyPairData()
    {
        // Generate a new X25519 key pair
        var (privateKey, publicKey) = X25519.GenerateKeyPair();

        // Convert to age format (Bech32)
        var privateKeyAge = KeyFileUtils.EncodeAgeSecretKey(privateKey);
        var publicKeyAge = KeyFileUtils.EncodeAgePublicKey(publicKey);

        return (privateKey, publicKey, privateKeyAge, publicKeyAge);
    }
}