using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Program = DotAge.Cli.Program;
using LoggerFactory = DotAge.Core.Logging.LoggerFactory;

// prevent the tests running in parallel to make life a bit easier when dealing with files and processes
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DotAge.Integration;

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
    private static readonly Program _cli = new();
    private static readonly KeyGen.Program _keyGen = new();
    private static readonly Lazy<ILogger> _logger = new(() => LoggerFactory.CreateLogger(nameof(TestUtils)));

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

                _logger.Value.LogWarning("Environment variable AGE_BINARY_PATH is set to '{Path}' but file does not exist.", envPath);
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

                _logger.Value.LogWarning("Environment variable AGE_KEYGEN_BINARY_PATH is set to '{Path}' but file does not exist.", envPath);
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

                _logger.Value.LogWarning("Environment variable RAGE_BINARY_PATH is set to '{Path}' but file does not exist.", envPath);
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

                _logger.Value.LogWarning("Environment variable RAGE_KEYGEN_BINARY_PATH is set to '{Path}' but file does not exist.", envPath);
            }

            var defaultPath = Path.Combine("/usr/local/bin", "rage-keygen");
            return File.Exists(defaultPath) ? defaultPath : null;
        }
    }

    /// <summary>
    ///     Validates that all required external binaries are available.
    /// </summary>
    /// <returns>True if all binaries are available, false otherwise.</returns>
    public static bool ValidateExternalBinaries()
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
            if (path == null)
            {
                _logger.Value.LogWarning(
                    $"External binary '{name}' not found. Set {name.ToUpper().Replace("-", "_")}_BINARY_PATH environment variable to specify custom path.");
                allAvailable = false;
            }
            else
            {
                _logger.Value.LogInformation($"Found {name} at: {path}");
            }

        return allAvailable;
    }

    /// <summary>
    ///     Runs a command asynchronously and returns the result.
    /// </summary>
    /// <param name="command">The command to run.</param>
    /// <param name="arguments">The arguments for the command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunCommandAsync(string command, string arguments, string? input = null)
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

        _logger.Value.LogTrace("Invoking command: {Command} {Arguments}", command, arguments);

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

        _logger.Value.LogTrace("Command stdout: {Stdout}", output);
        _logger.Value.LogTrace("Command stderr: {Stderr}", error);
        _logger.Value.LogTrace("Command exit code: {ExitCode}", process.ExitCode);

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
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunAgeAsync(string arguments, string? input = null)
    {
        if (AgeBinaryPath == null)
            throw new InvalidOperationException(
                "age binary not found. Set AGE_BINARY_PATH environment variable to specify custom path.");

        return await RunCommandAsync(AgeBinaryPath, arguments, input);
    }

    /// <summary>
    ///     Runs the age-keygen command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the age-keygen command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunAgeKeyGenAsync(string arguments, string? input = null)
    {
        if (AgeKeyGenBinaryPath == null)
            throw new InvalidOperationException(
                "age-keygen binary not found. Set AGE_KEYGEN_BINARY_PATH environment variable to specify custom path.");

        return await RunCommandAsync(AgeKeyGenBinaryPath, arguments, input);
    }

    /// <summary>
    ///     Runs the rage command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the rage command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunRageAsync(string arguments, string? input = null)
    {
        if (RageBinaryPath == null)
            throw new InvalidOperationException(
                "rage binary not found. Set RAGE_BINARY_PATH environment variable to specify custom path.");

        return await RunCommandAsync(RageBinaryPath, arguments, input);
    }

    /// <summary>
    ///     Runs the rage-keygen command using the located binary.
    /// </summary>
    /// <param name="arguments">The arguments for the rage-keygen command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunRageKeyGenAsync(string arguments, string? input = null)
    {
        if (RageKeyGenBinaryPath == null)
            throw new InvalidOperationException(
                "rage-keygen binary not found. Set RAGE_KEYGEN_BINARY_PATH environment variable to specify custom path.");

        return await RunCommandAsync(RageKeyGenBinaryPath, arguments, input);
    }

    /// <summary>
    ///     Runs the dotage CLI using the static Run method instead of external binary.
    /// </summary>
    /// <param name="arguments">The arguments for the dotage command.</param>
    /// <param name="input">Optional input to provide to the command.</param>
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunDotAgeAsync(string arguments, string? input = null)
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

            var exitCode = await _cli.RunAsync(args);

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
    /// <returns>A task that represents the asynchronous operation with the command result.</returns>
    public static async Task<CommandResult> RunDotAgeKeyGenAsync(string arguments)
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
            var exitCode = await _keyGen.RunAsync(args);

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
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task<CommandResult> RunDotAgeKeyGenWithOutputAsync(string outputPath)
    {
        return await RunDotAgeKeyGenAsync($"-o {outputPath}");
    }

    /// <summary>
    ///     Runs a command using the expect script to handle interactive passphrase input.
    ///     This uses the age_passphrase.exp script to automate passphrase entry.
    ///     Only use this for commands that require passphrase input (like age -e -p, rage -e -p).
    /// </summary>
    /// <param name="command">The command to run (e.g., 'age').</param>
    /// <param name="passphrase">The passphrase to provide.</param>
    /// <param name="arguments">The arguments for the command.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task<CommandResult> RunCommandWithExpectAsync(string command,
        string passphrase,
        string arguments)
    {
        // Get the path to the expect script in the output directory
        var expectScriptPath = Path.Combine(AppContext.BaseDirectory, "age_passphrase.exp");

        // Check if expect script exists
        if (!File.Exists(expectScriptPath))
            throw new InvalidOperationException($"Expect script not found at {expectScriptPath}");

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

        _logger.Value.LogInformation("Running command: {Command} {Arguments}", command, arguments);

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        _logger.Value.LogInformation("Command completed with exit code {ExitCode}", process.ExitCode);
        if (!string.IsNullOrEmpty(output))
            _logger.Value.LogDebug("Command stdout: {Output}", output);
        if (!string.IsNullOrEmpty(error))
            _logger.Value.LogDebug("Command stderr: {Error}", error);

        if (process.ExitCode != 0)
        {
            var errorMessage = $"Command '{command} {arguments}' failed with exit code {process.ExitCode}. " +
                               $"Output: {output}. Error: {error}";
            _logger.Value.LogError(errorMessage);
            throw new InvalidOperationException(errorMessage);
        }

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