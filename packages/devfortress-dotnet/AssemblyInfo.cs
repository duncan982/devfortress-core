using System.Runtime.CompilerServices;

// Exposes this assembly's `internal` members (e.g. AbuseIPDB's rate-limit counters/cache) to
// the SDK's own test project ONLY, so they can be exercised directly without widening
// visibility to any other assembly. This is the ONLY InternalsVisibleTo in this project.
//
// TODO 418: Tier2Gated used to be part of this same assembly and relied on this attribute too,
// but it has its own project now (Tier2Gated/DevFortress.Sdk.Tier2Gated.csproj, with its own
// identical InternalsVisibleTo in Tier2Gated/AssemblyInfo.cs) — a real packaging-level
// exclusion the main project's own `dotnet pack` can never ship, not just an access modifier.
[assembly: InternalsVisibleTo("DevFortress.Sdk.Tests")]
