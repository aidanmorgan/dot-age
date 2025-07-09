using System.Diagnostics;
using System.Text;
using DotAge.Cli;
using DotAge.KeyGen;
using Microsoft.Extensions.Logging;
using Xunit;

// prevent the tests running in parallel to make life a bit easier when dealing with files and processes
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DotAge.Tests;


/// <summary>
///     Utility class containing reusable methods for integration tests.
/// </summary>
public class CommandResult
{
    public string Stdout { get; set; } = string.Empty;
    public string Stderr { get; set; } = string.Empty;
    public int ExitCode { get; set; }
}

public static class TestUtils
{
    /// <summary>
    ///     Gets the path to the age binary.
    /// </summary>
    public static string? AgeBinaryPath
    {
        get
        {
            var envPath = Environment.GetEnvironmentVariable("AGE_BINARY_PATH");
            if (!string.IsNullOrEmpty(envPath))
            {
                if (File.Exists(envPath))
                    return envPath;
                
                Console.WriteLine($"Warning: Environment variable AGE_BINARY_PATH is set to '{envPath}' but file does not exist.");
            }

            var defaultPath = Path.Combine("/usr/local/bin", "age");
            return File.Exists(defaultPath) ? defaultPath : null;
        }
    }

    /// <summary>
    ///     Gets the path to the age-keygen binary.
    /// </summary>
    public static string? AgeKeyGenBinaryPath
    {
        get
        {
            var envPath = Environment.GetEnvironmentVariable("AGE_KEYGEN_BINARY_PATH");
            if (!string.IsNullOrEmpty(envPath))
            {
                if (File.Exists(envPath))
                    return envPath;
                
                Console.WriteLine($"Warning: Environment variable AGE_KEYGEN_BINARY_PATH is set to '{envPath}' but file does not exist.");
            }

            var defaultPath = Path.Combine("/usr/local/bin", "age-keygen");
            return File.Exists(defaultPath) ? defaultPath : null;
        }
    }

    /// <summary>
    ///     Gets the path to the rage binary.
    /// </summary>
    public static string? RageBinaryPath
    {
        get
        {
            var envPath = Environment.GetEnvironmentVariable("RAGE_BINARY_PATH");
            if (!string.IsNullOrEmpty(envPath))
            {
                if (File.Exists(envPath))
                    return envPath;
                
                Console.WriteLine($"Warning: Environment variable RAGE_BINARY_PATH is set to '{envPath}' but file does not exist.");
            }

            var defaultPath = Path.Combine("/usr/local/bin", "rage");
            return File.Exists(defaultPath) ? defaultPath : null;
        }
    }

    /// <summary>
    ///     Gets the path to the rage-keygen binary.
    /// </summary>
    public static string? RageKeyGenBinaryPath
    {
        get
        {
            var envPath = Environment.GetEnvironmentVariable("RAGE_KEYGEN_BINARY_PATH");
            if (!string.IsNullOrEmpty(envPath))
            {
                if (File.Exists(envPath))
                    return envPath;
                
                Console.WriteLine($"Warning: Environment variable RAGE_KEYGEN_BINARY_PATH is set to '{envPath}' but file does not exist.");
            }

            var defaultPath = Path.Combine("/usr/local/bin", "rage-keygen");
            return File.Exists(defaultPath) ? defaultPath : null;
        }
    }

    /// <summary>
    ///     Validates that all required external binaries are available.
    /// </summary>
    /// <param name="logger">Optional logger for output.</param>
    /// <returns>True if all binaries are available, false otherwise.</returns>
    public static bool ValidateExternalBinaries(ILogger? logger = null)
    {
        var binaries = new[]
        {
            ("age", AgeBinaryPath),
            ("age-keygen", AgeKeyGenBinaryPath),
            ("rage", RageBinaryPath),
            ("rage-keygen", RageKeyGenBinaryPath)
        };

        var allAvailable = true;
        foreach (var (name, path) in binaries)
        {
            if (path == null)
            {
                logger?.LogWarning($"External binary '{name}' not found. Set {name.ToUpper().Replace("-", "_")}_BINARY_PATH environment variable to specify custom path.");
                allAvailable = false;
            }
            else
            {
                logger?.LogInformation($"Found {name} at: {path}");
            }
        }

        return allAvailable;
    }

    /// <summary>
    ///     Runs a command asynchronously and returns the result.
    /// </summary>
    /// <param name="command">The command to run.</param>
    /// <param name="arguments">The arguments for the command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunCommandAsync(string command, string arguments, string? input = null,
        ILogger? logger = null)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = command,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input != null,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        if (input != null)
        {
            await process.StandardInput.WriteLineAsync(input);
            process.StandardInput.Close();
        }

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        return new CommandResult
        {
            Stdout = output,
            Stderr = error,
            ExitCode = process.ExitCode
        };
    }

    /// <summary>
    ///     Runs the age command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the age command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunAgeAsync(string arguments, string? input = null, ILogger? logger = null)
    {
        if (AgeBinaryPath == null)
        {
            throw new InvalidOperationException("age binary not found. Set AGE_BINARY_PATH environment variable to specify custom path.");
        }

        return await RunCommandAsync(AgeBinaryPath, arguments, input, logger);
    }

    /// <summary>
    ///     Runs the age-keygen command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the age-keygen command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunAgeKeyGenAsync(string arguments, string? input = null, ILogger? logger = null)
    {
        if (AgeKeyGenBinaryPath == null)
        {
            throw new InvalidOperationException("age-keygen binary not found. Set AGE_KEYGEN_BINARY_PATH environment variable to specify custom path.");
        }

        return await RunCommandAsync(AgeKeyGenBinaryPath, arguments, input, logger);
    }

    /// <summary>
    ///     Runs the rage command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the rage command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunRageAsync(string arguments, string? input = null, ILogger? logger = null)
    {
        if (RageBinaryPath == null)
        {
            throw new InvalidOperationException("rage binary not found. Set RAGE_BINARY_PATH environment variable to specify custom path.");
        }

        return await RunCommandAsync(RageBinaryPath, arguments, input, logger);
    }

    /// <summary>
    ///     Runs the rage-keygen command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the rage-keygen command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunRageKeyGenAsync(string arguments, string? input = null, ILogger? logger = null)
    {
        if (RageKeyGenBinaryPath == null)
        {
            throw new InvalidOperationException("rage-keygen binary not found. Set RAGE_KEYGEN_BINARY_PATH environment variable to specify custom path.");
        }

        return await RunCommandAsync(RageKeyGenBinaryPath, arguments, input, logger);
    }

    /// <summary>
    ///     Runs the dotage CLI using the static Run method instead of external binary.
    /// </summary>
    /// <param name="arguments">The arguments for the dotage command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunDotAgeAsync(string arguments, string? input = null, ILogger? logger = null)
    {
        // Capture console output by redirecting it
        var originalOut = Console.Out;
        var originalErr = Console.Error;
        var originalIn = Console.In;

        try
        {
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            using var stdin = input != null ? new StringReader(input) : new StringReader("");

            Console.SetOut(stdout);
            Console.SetError(stderr);
            Console.SetIn(stdin);

            // Parse arguments
            var args = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            
            // Run the dotage CLI
            var exitCode = await new DotAgeCliApp().InvokeAsync(args, logger);

            return new CommandResult
            {
                Stdout = stdout.ToString(),
                Stderr = stderr.ToString(),
                ExitCode = exitCode
            };
        }
        finally
        {
            // restore the stdout/in/err back to what they were before
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
            Console.SetIn(originalIn);
        }
    }

    /// <summary>
    ///     Runs the dotage-keygen CLI using the static Run method instead of external binary.
    /// </summary>
    /// <param name="arguments">The arguments for the dotage-keygen command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunDotAgeKeyGenAsync(string arguments, ILogger? logger = null)
    {
        // Capture console output by redirecting it
        var originalOut = Console.Out;
        var originalErr = Console.Error;

        try
        {
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();

            Console.SetOut(stdout);
            Console.SetError(stderr);

            // Parse arguments
            var args = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            
            // Run the dotage-keygen CLI
            var exitCode = DotAge.KeyGen.Program.Run(args);

            return new CommandResult
            {
                Stdout = stdout.ToString(),
                Stderr = stderr.ToString(),
                ExitCode = exitCode
            };
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalErr);
        }
    }

    /// <summary>
    ///     Generates a key pair using dotage-keygen and returns the result.
    ///     This method uses the static Run method instead of external binary.
    /// </summary>
    /// <param name="outputPath">The path to write the key file to.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task<CommandResult> RunDotAgeKeyGenWithOutputAsync(string outputPath, ILogger? logger = null)
    {
        return await RunDotAgeKeyGenAsync($"-o {outputPath}", logger);
    }

    /// <summary>
    ///     Runs a command using the expect script to handle interactive passphrase input.
    ///     This uses the age_passphrase.exp script to automate passphrase entry.
    ///     Only use this for commands that require passphrase input (like age -e -p, rage -e -p).
    /// </summary>
    /// <param name="command">The command to run (e.g., 'age').</param>
    /// <param name="passphrase">The passphrase to provide.</param>
    /// <param name="arguments">The arguments for the command.</param>
    /// <param name="logger">Optional logger for debug output.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task<CommandResult> RunCommandWithExpectAsync(string command,
        string passphrase,
        string arguments,
        ILogger logger = null)
    {
        // Get the path to the expect script in the output directory
        var expectScriptPath = Path.Combine(AppContext.BaseDirectory, "age_passphrase.exp");

        // Make sure the expect script is executable
        // Split arguments into individual arguments for the expect script
        var argumentList = new List<string> { $"\"{passphrase}\"", $"\"{command}\"" };
        argumentList.AddRange(arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries));

        var startInfo = new ProcessStartInfo
        {
            FileName = expectScriptPath,
            Arguments = string.Join(" ", argumentList),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Command '{command} {arguments}' failed with exit code {process.ExitCode}. " +
                $"Output: {output}. Error: {error}");


        return new CommandResult
        {
            Stdout = output,
            Stderr = error,
            ExitCode = process.ExitCode
        };
    }

    /// <summary>
    ///     Creates a temporary directory for testing.
    /// </summary>
    /// <param name="prefix">Prefix for the directory name.</param>
    /// <returns>The path to the created temporary directory.</returns>
    public static string CreateTempDirectory(string prefix = "dotage-tests")
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);
        return tempDir;
    }

    /// <summary>
    ///     Safely deletes a directory, ignoring any errors.
    /// </summary>
    /// <param name="directoryPath">The path to the directory to delete.</param>
    public static void SafeDeleteDirectory(string directoryPath)
    {
        try
        {
            if (Directory.Exists(directoryPath)) Directory.Delete(directoryPath, true);
        }
        catch
        {
            // Ignore cleanup errors
        }
    }
}