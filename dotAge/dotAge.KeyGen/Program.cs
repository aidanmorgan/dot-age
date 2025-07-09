using System.CommandLine;
using System.Globalization;
using DotAge.Core.Crypto;
using DotAge.Core.Utils;

namespace DotAge.KeyGen;

public class Program
{
    private static readonly string DotAgeVersion = "0.0.1-alpha";

    private static int Main(string[] args)
    {
        return Run(args);
    }

    public static int Run(string[] args)
    {
        var outputOption = new Option<string>(
            new[] { "-o", "--output" },
            "Write the key pair to the specified file instead of standard output"
        );

        var rootCommand = new RootCommand("Generate a new age key pair")
        {
            outputOption
        };

        rootCommand.SetHandler(output => GenerateKeyPair(output), outputOption);

        return rootCommand.Invoke(args);

    }

    public static int GenerateKeyPair(string output)
    {
        try
        {
            var keyOutput = GenerateKeyPairContent();

            // Write the output
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
                var lines = keyOutput.Split('\n');
                foreach (var line in lines)
                    if (line.StartsWith("# public key: "))
                    {
                        Console.WriteLine($"Public key: {line.Substring("# public key: ".Length)}");
                        break;
                    }
            }

            return 0; // Success
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error generating key pair: {ex.Message}");
            return 1; // Error
        }
    }

    /// <summary>
    ///     Generates a new age key pair and returns the formatted content.
    ///     This method can be called from tests to generate keys programmatically.
    /// </summary>
    /// <returns>The formatted key pair content in age format.</returns>
    public static string GenerateKeyPairContent()
    {
        // Generate a new X25519 key pair
        var (privateKey, publicKey) = X25519.GenerateKeyPair();

        // Convert to age format (Bech32)
        var privateKeyAge = KeyFileUtils.EncodeAgeSecretKey(privateKey);
        var publicKeyAge = KeyFileUtils.EncodeAgePublicKey(publicKey);

        // Format the output in standard age format (matching age-keygen exactly)
        return
            $"# created: {DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)}\n# public key: {publicKeyAge}\n{privateKeyAge}";
    }

    /// <summary>
    ///     Generates a new age key pair and returns the key components.
    ///     This method can be called from tests to get the raw key data.
    /// </summary>
    /// <returns>A tuple containing (privateKeyBytes, publicKeyBytes, privateKeyAge, publicKeyAge).</returns>
    public static (byte[] privateKeyBytes, byte[] publicKeyBytes, string privateKeyAge, string publicKeyAge)
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