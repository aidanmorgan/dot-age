using System.Text.RegularExpressions;
using DotAge.Core.Exceptions;
using DotAge.Core.Logging;
using Microsoft.Extensions.Logging;

namespace DotAge.Core.Utils;

/// <summary>
///     Utility methods for working with key files.
/// </summary>
public static class KeyFileUtils
{
    private static readonly Lazy<ILogger> Logger = new Lazy<ILogger>(() => DotAge.Core.Logging.LoggerFactory.CreateLogger(nameof(KeyFileUtils)));

    private static readonly Regex AgeSecretKeyRegex =
        new(@"^AGE-SECRET-KEY-1[A-Z0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex AgePublicKeyRegex = new(@"^age1[0-9a-z]{58,63}$", RegexOptions.Compiled);

    /// <summary>
    ///     Parses a key file and extracts the private and public keys (official age format).
    ///     Matches the Go and Rust implementations exactly.
    /// </summary>
    /// <param name="keyFilePath">The path to the key file.</param>
    /// <returns>A tuple containing the private key line and public key line.</returns>
    public static (string privateKeyLine, string publicKeyLine) ParseKeyFile(string keyFilePath)
    {
        if (string.IsNullOrEmpty(keyFilePath))
            throw new ArgumentNullException(nameof(keyFilePath));

        if (!File.Exists(keyFilePath))
            throw new AgeKeyException($"Key file not found: {keyFilePath}");

        Logger.Value.LogTrace("Parsing key file: {KeyFilePath}", keyFilePath);

        var keyFileContent = File.ReadAllText(keyFilePath);
        var lines = keyFileContent.Split('\n');

        string? privateKeyLine = null;
        string? publicKeyLine = null;

        // Parse lines exactly like Go/Rust implementations
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmedLine = line.Trim();

            // Extract public key from any comment line if present (robust to whitespace)
            if (trimmedLine.StartsWith("# public key: "))
            {
                var publicKey = trimmedLine.Substring("# public key: ".Length).Trim();
                if (AgePublicKeyRegex.IsMatch(publicKey)) 
                {
                    publicKeyLine = publicKey;
                    Logger.Value.LogTrace("Found public key in comment: {PublicKey}", publicKey);
                }
            }

            // Skip empty lines and comment lines (matching Go/Rust behavior)
            if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#")) 
            {
                continue;
            }

            // Check for private key (AGE-SECRET-KEY format)
            if (trimmedLine.StartsWith("AGE-SECRET-KEY-", StringComparison.OrdinalIgnoreCase))
            {
                if (privateKeyLine != null)
                {
                    Logger.Value.LogTrace("Multiple private keys found in key file");
                    throw new AgeKeyException("Multiple private keys found in key file");
                }
                privateKeyLine = trimmedLine;
                Logger.Value.LogTrace("Found private key: {PrivateKey}", privateKeyLine);
            }
            // Check for public key (age1... format) - standalone line
            else if (trimmedLine.StartsWith("age1"))
            {
                if (AgePublicKeyRegex.IsMatch(trimmedLine))
                {
                    if (publicKeyLine != null)
                    {
                        Logger.Value.LogTrace("Multiple public keys found in key file");
                        throw new AgeKeyException("Multiple public keys found in key file");
                    }
                    publicKeyLine = trimmedLine;
                    Logger.Value.LogTrace("Found public key: {PublicKey}", publicKeyLine);
                }
            }
            else
            {
                Logger.Value.LogTrace("Invalid key format on line {LineNumber}: {Line}", i + 1, trimmedLine);
                throw new AgeKeyException($"Invalid key format on line {i + 1}");
            }
        }

        if (privateKeyLine == null)
        {
            Logger.Value.LogTrace("Private key not found in the key file");
            throw new AgeKeyException("Private key not found in the key file.");
        }

        if (publicKeyLine == null)
        {
            Logger.Value.LogTrace("Public key not found in the key file");
            throw new AgeKeyException("Public key not found in the key file.");
        }

        Logger.Value.LogTrace("Successfully parsed key file - Private: {PrivateKey}, Public: {PublicKey}", 
            privateKeyLine, publicKeyLine);

        return (privateKeyLine, publicKeyLine);
    }

    /// <summary>
    ///     Parses a key file and extracts the private and public keys as byte arrays (X25519 raw keys).
    /// </summary>
    /// <param name="keyFilePath">The path to the key file.</param>
    /// <returns>A tuple containing the private key and public key as byte arrays.</returns>
    public static (byte[] privateKey, byte[] publicKey) ParseKeyFileAsBytes(string keyFilePath)
    {
        Logger.Value.LogTrace("Parsing key file as bytes: {KeyFilePath}", keyFilePath);

        var (privateKeyLine, publicKeyLine) = ParseKeyFile(keyFilePath);
        var privateKey = DecodeAgeSecretKey(privateKeyLine);
        var publicKey = DecodeAgePublicKey(publicKeyLine);

        return (privateKey, publicKey);
    }

    /// <summary>
    ///     Decodes an "AGE-SECRET-KEY-1..." line to a 32-byte X25519 private key.
    /// </summary>
    public static byte[] DecodeAgeSecretKey(string privateKeyLine)
    {
        if (privateKeyLine == null) throw new ArgumentNullException(nameof(privateKeyLine));

        var m = AgeSecretKeyRegex.Match(privateKeyLine);
        if (!m.Success)
        {
            Logger.Value.LogTrace("Invalid AGE-SECRET-KEY format");
            throw new AgeKeyException("Invalid AGE-SECRET-KEY format");
        }

        var bech32 = privateKeyLine.Trim();
        var (hrp, data) = Bech32.Decode(bech32);

        Logger.Value.LogTrace("Bech32 decoded - HRP: {Hrp}, Data length: {DataLength}", hrp, data.Length);

        // Accept both uppercase and lowercase HRP for secret keys
        if (!string.Equals(hrp, "AGE-SECRET-KEY-", StringComparison.OrdinalIgnoreCase))
        {
            Logger.Value.LogTrace("Invalid AGE-SECRET-KEY HRP: {Hrp}", hrp);
            throw new AgeKeyException("Invalid AGE-SECRET-KEY format");
        }

        // Bech32.Decode already converts 5-bit to 8-bit, so just validate length
        if (data.Length != 32)
        {
            Logger.Value.LogTrace("Invalid AGE-SECRET-KEY length: {DataLength} (expected 32)", data.Length);
            throw new AgeKeyException("Invalid AGE-SECRET-KEY length");
        }

        return data;
    }

    /// <summary>
    ///     Decodes an "age1..." line to a 32-byte X25519 public key.
    /// </summary>
    public static byte[] DecodeAgePublicKey(string publicKeyLine)
    {
        if (publicKeyLine == null) throw new ArgumentNullException(nameof(publicKeyLine));

        var m = AgePublicKeyRegex.Match(publicKeyLine);
        if (!m.Success)
        {
            Logger.Value.LogTrace("Invalid age public key format");
            throw new AgeKeyException("Invalid age public key format");
        }

        var bech32 = publicKeyLine.Trim();
        var (hrp, data) = Bech32.Decode(bech32);

        Logger.Value.LogTrace("Bech32 decoded - HRP: {Hrp}, Data length: {DataLength}", hrp, data.Length);

        // Only accept lowercase HRP for public keys (matching age implementation)
        if (!string.Equals(hrp, "age", StringComparison.Ordinal))
        {
            Logger.Value.LogTrace("Invalid age public key HRP: {Hrp}", hrp);
            throw new AgeKeyException("Invalid age public key format");
        }

        // Bech32.Decode already converts 5-bit to 8-bit, so just validate length
        if (data.Length != 32)
        {
            Logger.Value.LogTrace("Invalid age public key length: {DataLength} (expected 32)", data.Length);
            throw new AgeKeyException("Invalid age public key length");
        }

        Logger.Value.LogTrace("Successfully decoded age public key length: {PublicKeyLength} bytes", data.Length);
        return data;
    }

    /// <summary>
    ///     Encodes a 32-byte X25519 private key to age secret key format (Bech32).
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The age secret key string.</returns>
    public static string EncodeAgeSecretKey(byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != 32)
            throw new AgeKeyException("Private key must be 32 bytes");

        // Encode as Bech32 with "AGE-SECRET-KEY-" HRP (case sensitive as per age spec)
        var bech32 = Bech32.Encode("AGE-SECRET-KEY-", privateKey).ToUpperInvariant();
        // Remove any trailing non-alphanumeric characters (e.g., '%')
        bech32 = bech32.TrimEnd('\r', '\n', '%');

        return bech32;
    }

    /// <summary>
    ///     Encodes a 32-byte X25519 public key to age public key format (Bech32).
    /// </summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <returns>The age public key string.</returns>
    public static string EncodeAgePublicKey(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != 32)
            throw new AgeKeyException("Public key must be 32 bytes");

        // Encode as Bech32 with "age" HRP (lowercase as per age spec)
        var result = Bech32.Encode("age", publicKey);

        return result;
    }

    /// <summary>
    ///     Reads recipients from a file (or stdin if path is "-"). Skips empty lines and lines starting with '#'.
    /// </summary>
    /// <param name="recipientsFilePath">The path to the recipients file, or "-" for stdin.</param>
    /// <returns>A list of recipient strings.</returns>
    public static List<string> ReadRecipientsFile(string recipientsFilePath)
    {
        Logger.Value.LogTrace("Reading recipients file: {RecipientsFilePath}", recipientsFilePath);

        var recipients = new List<string>();
        IEnumerable<string> lines;
        if (recipientsFilePath == "-")
        {
            using var reader = new StreamReader(Console.OpenStandardInput());
            lines = ReadLines(reader);
        }
        else
        {
            lines = File.ReadLines(recipientsFilePath);
        }

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                continue;
            recipients.Add(trimmed);
        }

        return recipients;
    }

    private static IEnumerable<string> ReadLines(TextReader reader)
    {
        while (reader.ReadLine() is { } line) yield return line;
    }
}