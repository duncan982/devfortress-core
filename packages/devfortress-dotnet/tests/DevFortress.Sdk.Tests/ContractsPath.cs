using System.Runtime.CompilerServices;

namespace DevFortress.Sdk.Tests;

/// <summary>Resolves a file under the repo-root <c>contracts/</c> directory relative to this source file's own location, so it works regardless of the test runner's working directory.</summary>
internal static class ContractsPath
{
    public static string For(string fileName, [CallerFilePath] string sourceFile = "")
    {
        string dir = Path.GetDirectoryName(sourceFile)!;
        return Path.GetFullPath(Path.Combine(dir, "..", "..", "..", "..", "contracts", fileName));
    }
}
