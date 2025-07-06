using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using dotAge.Core.Crypto;
using Xunit;

namespace dotAge.Tests.Integration
{
    public class KeyGenTests
    {
        [Fact]
        public void KeyGen_GeneratesValidKeyPair()
        {
            // Arrange
            var outputFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                // Act - Run the KeyGen program
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dotnet",
                        Arguments = $"run --project {Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "dotAge.KeyGen", "dotAge.KeyGen.csproj")} -- -o {outputFile}",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                // Assert
                Assert.Equal(0, process.ExitCode);
                Assert.True(File.Exists(outputFile), "Output file should exist");

                // Read the generated key file
                var keyFileContent = File.ReadAllText(outputFile);
                var lines = keyFileContent.Split('\n');

                // Verify the private key format
                Assert.StartsWith(X25519.PrivateKeyPrefix, lines[0]);

                // Verify the public key format
                Assert.StartsWith("# public key: " + X25519.PublicKeyPrefix, lines[1]);

                // Extract the keys
                var privateKeyLine = lines[0].Trim();
                var publicKeyLine = lines[1].Trim().Substring("# public key: ".Length);

                // Verify that the keys can be decoded
                var privateKey = X25519.DecodePrivateKey(privateKeyLine);
                var publicKey = X25519.DecodePublicKey(publicKeyLine);

                // Verify that the public key can be derived from the private key
                var curve25519 = new Curve25519.NetCore.Curve25519();
                var derivedPublicKey = curve25519.GetPublicKey(privateKey);
                Assert.Equal(publicKey, derivedPublicKey);

                // Verify the console output
                Assert.Contains($"Key pair written to {outputFile}", output);
                Assert.Contains($"Public key: {publicKeyLine}", output);
            }
            finally
            {
                // Clean up
                if (File.Exists(outputFile))
                    File.Delete(outputFile);
            }
        }

        [Fact]
        public void KeyGen_OutputMatchesAgeKeygenFormat()
        {
            // Skip if age-keygen command is not available
            var ageKeygenCommand = FindAgeKeygenExecutable();
            if (ageKeygenCommand == null)
            {
                return;
            }

            // Arrange
            var ageKeygenOutputFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            var dotAgeKeygenOutputFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                // Generate a key pair using the original age-keygen
                RunProcess(ageKeygenCommand, $"-o {ageKeygenOutputFile}");

                // Generate a key pair using dotAge.KeyGen
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dotnet",
                        Arguments = $"run --project {Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "dotAge.KeyGen", "dotAge.KeyGen.csproj")} -- -o {dotAgeKeygenOutputFile}",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                // Read the key files
                var ageKeygenContent = File.ReadAllText(ageKeygenOutputFile);
                var dotAgeKeygenContent = File.ReadAllText(dotAgeKeygenOutputFile);

                // Verify the format matches
                var ageKeygenLines = ageKeygenContent.Split('\n');
                var dotAgeKeygenLines = dotAgeKeygenContent.Split('\n');

                // Both should have at least 2 lines
                Assert.True(ageKeygenLines.Length >= 2);
                Assert.True(dotAgeKeygenLines.Length >= 2);

                // Verify the private key format
                Assert.StartsWith(X25519.PrivateKeyPrefix, ageKeygenLines[0]);
                Assert.StartsWith(X25519.PrivateKeyPrefix, dotAgeKeygenLines[0]);

                // Verify the public key format
                Assert.StartsWith("# public key: " + X25519.PublicKeyPrefix, ageKeygenLines[1]);
                Assert.StartsWith("# public key: " + X25519.PublicKeyPrefix, dotAgeKeygenLines[1]);

                // Verify the private key length
                var agePrivateKeyBase64 = ageKeygenLines[0].Substring(X25519.PrivateKeyPrefix.Length);
                var dotAgePrivateKeyBase64 = dotAgeKeygenLines[0].Substring(X25519.PrivateKeyPrefix.Length);
                Assert.Equal(agePrivateKeyBase64.Length, dotAgePrivateKeyBase64.Length);

                // Verify the public key length
                var agePublicKeyBase64 = ageKeygenLines[1].Substring("# public key: ".Length + X25519.PublicKeyPrefix.Length);
                var dotAgePublicKeyBase64 = dotAgeKeygenLines[1].Substring("# public key: ".Length + X25519.PublicKeyPrefix.Length);
                Assert.Equal(agePublicKeyBase64.Length, dotAgePublicKeyBase64.Length);
            }
            finally
            {
                // Clean up
                if (File.Exists(ageKeygenOutputFile))
                    File.Delete(ageKeygenOutputFile);

                if (File.Exists(dotAgeKeygenOutputFile))
                    File.Delete(dotAgeKeygenOutputFile);
            }
        }

        private string FindAgeKeygenExecutable()
        {
            // Paths to check for the FiloSottile/age executables
            var possiblePaths = new[]
            {
                // Common installation paths
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                // Homebrew paths
                "/opt/homebrew/bin",
                // Go paths
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "go", "bin"),
                // Current directory and PATH
                Directory.GetCurrentDirectory()
            };

            // First check if the executable is in one of the possible paths
            foreach (var path in possiblePaths)
            {
                var fullPath = Path.Combine(path, "age-keygen");
                if (File.Exists(fullPath))
                {
                    return fullPath;
                }
            }

            // Then check if it's in the PATH
            var pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathEnv))
            {
                var pathSeparator = Environment.OSVersion.Platform == PlatformID.Win32NT ? ';' : ':';
                var paths = pathEnv.Split(pathSeparator);

                foreach (var path in paths)
                {
                    var fullPath = Path.Combine(path, "age-keygen");
                    if (File.Exists(fullPath))
                    {
                        return fullPath;
                    }
                }
            }

            // If we get here, we couldn't find the executable
            return null;
        }

        private void RunProcess(string command, string arguments, string input = null, int timeoutSeconds = 10)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo };

            // Set up asynchronous reading of output and error streams to prevent deadlocks
            var outputReader = new System.Threading.Tasks.Task<string>(() => process.StandardOutput.ReadToEnd());
            var errorReader = new System.Threading.Tasks.Task<string>(() => process.StandardError.ReadToEnd());

            process.Start();

            // Start reading from output and error streams
            outputReader.Start();
            errorReader.Start();

            if (!string.IsNullOrEmpty(input))
            {
                process.StandardInput.WriteLine(input);
                process.StandardInput.Close();
            }
            else
            {
                // Close standard input if no input is provided
                process.StandardInput.Close();
            }

            // Wait for the process to exit with timeout
            bool exited = process.WaitForExit(timeoutSeconds * 1000);

            if (!exited)
            {
                // Process did not exit within the timeout period, kill it
                process.Kill();
                throw new TimeoutException($"Process {command} {arguments} did not complete within {timeoutSeconds} seconds and was terminated.");
            }

            // Wait for the output and error readers to complete
            System.Threading.Tasks.Task.WaitAll(outputReader, errorReader);

            // Get the output and error
            var output = outputReader.Result;
            var error = errorReader.Result;

            if (process.ExitCode != 0)
            {
                throw new Exception($"Process exited with code {process.ExitCode}: {error}");
            }
        }
    }
}
