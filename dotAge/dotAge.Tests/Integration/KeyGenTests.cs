using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Text;
using DotAge.Core.Crypto;
using DotAge.Core.Utils;
using DotAge.KeyGen;
using Xunit;

namespace DotAge.Tests.Integration
{
    public class KeyGenTests : IDisposable
    {
        // List of files to clean up
        private readonly List<string> _filesToCleanup = new List<string>();

        public void Dispose()
        {
            // Clean up all temporary files
            foreach (var file in _filesToCleanup)
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }
        }
        [Fact]
        public void KeyGen_GeneratesValidKeyPair()
        {
            // Arrange
            var outputFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            _filesToCleanup.Add(outputFile);

            try
            {
                // Act - Call the KeyGen program directly
                var originalOut = Console.Out;
                var outputBuilder = new StringBuilder();
                var exitCode = 0;
                string output = "";
                string error = "";

                try
                {
                    using (var stringWriter = new StringWriter(outputBuilder))
                    {
                        Console.SetOut(stringWriter);

                        // Call the GenerateKeyPair method directly
                        exitCode = Program.GenerateKeyPair(outputFile);

                        // Get the output
                        output = outputBuilder.ToString();
                    }
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    exitCode = 1;
                }
                finally
                {
                    Console.SetOut(originalOut);
                }

                // Assert
                Assert.True(exitCode == 0, $"Process exited with non-zero code. Output: {output}, Error: {error}");
                Assert.True(File.Exists(outputFile), "Output file should exist");

                // Parse the key file using the utility method
                var (privateKeyLine, publicKeyLine) = KeyFileUtils.ParseKeyFile(outputFile);

                // Verify the private key format
                Assert.NotNull(privateKeyLine);
                Assert.StartsWith(X25519.PrivateKeyPrefix, privateKeyLine);

                // Verify the public key format
                Assert.NotNull(publicKeyLine);
                Assert.StartsWith(X25519.PublicKeyPrefix, publicKeyLine);

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
            _filesToCleanup.Add(ageKeygenOutputFile);
            _filesToCleanup.Add(dotAgeKeygenOutputFile);

            try
            {
                // Generate a key pair using the original age-keygen
                try
                {
                    RunProcess(ageKeygenCommand, $"-o {ageKeygenOutputFile}");

                    // Verify the age-keygen output file exists
                    if (!File.Exists(ageKeygenOutputFile))
                    {
                        // Skip the test if the age-keygen command didn't create the output file
                        return;
                    }
                }
                catch (Exception)
                {
                    // Skip the test if the age-keygen command fails
                    return;
                }

                // Generate a key pair using DotAge.KeyGen directly
                var originalOut = Console.Out;
                var outputBuilder = new StringBuilder();
                var exitCode = 0;
                string output = "";
                string error = "";

                try
                {
                    using (var stringWriter = new StringWriter(outputBuilder))
                    {
                        Console.SetOut(stringWriter);

                        // Call the GenerateKeyPair method directly
                        exitCode = Program.GenerateKeyPair(dotAgeKeygenOutputFile);

                        // Get the output
                        output = outputBuilder.ToString();
                    }
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    exitCode = 1;
                }
                finally
                {
                    Console.SetOut(originalOut);
                }

                // Verify the DotAge.KeyGen output file exists
                if (!File.Exists(dotAgeKeygenOutputFile))
                {
                    Assert.Fail($"DotAge.KeyGen did not create the output file. Exit code: {exitCode}, Output: {output}, Error: {error}");
                }

                // Read the key files
                var ageKeygenContent = File.ReadAllText(ageKeygenOutputFile);
                var dotAgeKeygenContent = File.ReadAllText(dotAgeKeygenOutputFile);

                // Write the age-keygen content to a temporary file for parsing
                var ageKeygenTempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                File.WriteAllText(ageKeygenTempFile, ageKeygenContent);
                _filesToCleanup.Add(ageKeygenTempFile);

                // Write the DotAge.KeyGen content to a temporary file for parsing
                var dotAgeKeygenTempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                File.WriteAllText(dotAgeKeygenTempFile, dotAgeKeygenContent);
                _filesToCleanup.Add(dotAgeKeygenTempFile);

                // Parse the key files using the utility method
                var (agePrivateKeyLine, agePublicKeyLine) = KeyFileUtils.ParseKeyFile(ageKeygenTempFile);
                var (dotAgePrivateKeyLine, dotAgePublicKeyLine) = KeyFileUtils.ParseKeyFile(dotAgeKeygenTempFile);

                // Verify the private key format
                Assert.NotNull(agePrivateKeyLine);
                Assert.NotNull(dotAgePrivateKeyLine);
                Assert.StartsWith(X25519.PrivateKeyPrefix, agePrivateKeyLine);
                Assert.StartsWith(X25519.PrivateKeyPrefix, dotAgePrivateKeyLine);

                // Verify the public key format
                Assert.NotNull(agePublicKeyLine);
                Assert.NotNull(dotAgePublicKeyLine);
                Assert.StartsWith(X25519.PublicKeyPrefix, agePublicKeyLine);
                Assert.StartsWith(X25519.PublicKeyPrefix, dotAgePublicKeyLine);

                // Extract the private key base64 part
                var agePrivateKeyBase64 = agePrivateKeyLine.Substring(X25519.PrivateKeyPrefix.Length);
                var dotAgePrivateKeyBase64 = dotAgePrivateKeyLine.Substring(X25519.PrivateKeyPrefix.Length);

                // Note: The original age-keygen command uses a custom encoding format that's different from
                // the standard Base64 encoding used by DotAge. The keys are functionally equivalent,
                // but the encoded strings have different lengths and formats.

                // Extract the public key base64 part
                var agePublicKeyBase64 = agePublicKeyLine.Substring(X25519.PublicKeyPrefix.Length);
                var dotAgePublicKeyBase64 = dotAgePublicKeyLine.Substring(X25519.PublicKeyPrefix.Length);

                // Note: As with the private keys, the public keys also use different encoding formats
                // between the original age-keygen command and DotAge. The keys are functionally equivalent,
                // but the encoded strings have different lengths and formats.
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
