using System;
using System.IO;
using System.CommandLine;

using System.CommandLine.Invocation;
using System.Globalization;
using DotAge.Core.Crypto;

namespace DotAge.KeyGen
{
    public class Program
    {
        private static readonly string DotAgeVersion = "0.0.1-alpha";

        static int Main(string[] args)
        {
            var outputOption = new Option<string>(
                new[] { "-o", "--output" },
                "Write the key pair to the specified file instead of standard output"
            );

            var rootCommand = new RootCommand("Generate a new age key pair")
            {
                outputOption
            };

            rootCommand.SetHandler((string output) => GenerateKeyPair(output), outputOption);

            return rootCommand.Invoke(args);
        }

        public static int GenerateKeyPair(string output)
        {
            try
            {
                // Generate a new X25519 key pair
                var (privateKey, publicKey) = X25519.GenerateKeyPair();

                // Encode the keys
                var encodedPrivateKey = X25519.EncodePrivateKey(privateKey);
                var encodedPublicKey = X25519.EncodePublicKey(publicKey);

                // Format the output
                var keyOutput = $"{encodedPrivateKey}\n# public key: {encodedPublicKey}\n# created: {DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)} by DotAge {DotAgeVersion}";

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
                    Console.WriteLine($"Public key: {encodedPublicKey}");
                }

                return 0; // Success
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error generating key pair: {ex.Message}");
                return 1; // Error
            }
        }
    }
}
