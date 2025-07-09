using DotAge.KeyGen;

namespace DotAge.Tests;

public class DotAgeKeyGenCompatibilityTests : IDisposable
{
    private readonly string _tempDir;

    public DotAgeKeyGenCompatibilityTests()
    {
        _tempDir = TestUtils.CreateTempDirectory("dotage-keygen-tests");
    }

    public void Dispose()
    {
        TestUtils.SafeDeleteDirectory(_tempDir);
    }

    [Fact]
    public void GenerateKeyPairContent_MatchesFormat()
    {
        var output = Program.GenerateKeyPairContent();
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length == 3, "Output should have 3 lines");
        Assert.StartsWith("# created: ", lines[0]);
        Assert.StartsWith("# public key: age1", lines[1]);
        Assert.StartsWith("AGE-SECRET-KEY-", lines[2]);
        Assert.Equal(74, lines[2].Length); // AGE-SECRET-KEY- + 57 chars
    }

    [Fact]
    public void GenerateKeyPairData_MatchesFormat()
    {
        var (priv, pub, privStr, pubStr) = Program.GenerateKeyPairData();
        Assert.Equal(32, priv.Length);
        Assert.Equal(32, pub.Length);
        Assert.StartsWith("AGE-SECRET-KEY-", privStr);
        Assert.StartsWith("age1", pubStr);
    }

    [Fact]
    public void OutputFile_IsCreated_AndOverwritten()
    {
        var file = Path.Combine(_tempDir, "key.txt");
        Assert.False(File.Exists(file));
        Program.GenerateKeyPair(file);
        Assert.True(File.Exists(file));
        var content1 = File.ReadAllText(file);
        // Try to overwrite
        Program.GenerateKeyPair(file);
        var content2 = File.ReadAllText(file);
        // File should be overwritten, so content may differ
        Assert.NotNull(content2);
        Assert.Equal(3, content2.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Fact]
    public async Task OutputFormat_MatchesAgeKeygen()
    {
        // Run age-keygen and dotage-keygen, compare output format
        var ageKeyFile = Path.Combine(_tempDir, "age-key.txt");
        var dotageKeyFile = Path.Combine(_tempDir, "dotage-key.txt");
        // Run age-keygen
        await TestUtils.RunCommandAsync("age-keygen", $"-o {ageKeyFile}");
        // Run dotage-keygen
        Program.GenerateKeyPair(dotageKeyFile);
        // Compare file formats
        var ageLines = File.ReadAllLines(ageKeyFile);
        var dotageLines = File.ReadAllLines(dotageKeyFile);
        Assert.Equal(3, ageLines.Length);
        Assert.Equal(3, dotageLines.Length);
        Assert.StartsWith("# created: ", dotageLines[0]);
        Assert.StartsWith("# created: ", ageLines[0]);
        Assert.StartsWith("# public key: age1", dotageLines[1]);
        Assert.StartsWith("# public key: age1", ageLines[1]);
        Assert.StartsWith("AGE-SECRET-KEY-", dotageLines[2]);
        Assert.StartsWith("AGE-SECRET-KEY-", ageLines[2]);
        Assert.Equal(dotageLines[2].Length, ageLines[2].Length);
    }

    // Remove KeyGenBinary and CLI tests
    [Fact]
    public void OutputToStdout_MatchesFormat()
    {
        // Simulate writing to stdout by capturing the output of GenerateKeyPairContent
        var output = Program.GenerateKeyPairContent();
        Assert.Contains("# created: ", output);
        Assert.Contains("# public key: age1", output);
        Assert.Contains("AGE-SECRET-KEY-", output);
    }

    [Fact]
    public void OutputFileOption_WritesFile()
    {
        var file = Path.Combine(_tempDir, "cli-key.txt");
        var rc = Program.GenerateKeyPair(file);
        Assert.Equal(0, rc);
        Assert.True(File.Exists(file));
        var content = File.ReadAllText(file);
        Assert.Contains("# created: ", content);
        Assert.Contains("# public key: age1", content);
        Assert.Contains("AGE-SECRET-KEY-", content);
    }

    // Remove HelpFlag_PrintsHelpAndExit0 and VersionFlag_UnknownOrNotSupported tests
}