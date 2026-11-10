using System.Text.Json;
using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>Byte-for-byte against the shared cross-language vectors (<c>contracts/webhook-signature-vectors.json</c>, repo root).</summary>
public class WebhookVerifierVectorsTests
{
    private static readonly string VectorsPath = ContractsPath.For("webhook-signature-vectors.json");

    private static JsonElement LoadVectors()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorsPath));
        return doc.RootElement.GetProperty("vectors").Clone();
    }

    public static IEnumerable<object[]> VectorNames()
    {
        foreach (var vector in LoadVectors().EnumerateArray())
        {
            yield return [vector.GetProperty("name").GetString()!];
        }
    }

    [Fact]
    public void ExpectsAtLeast15Vectors()
    {
        Assert.True(LoadVectors().GetArrayLength() >= 15);
    }

    [Theory]
    [MemberData(nameof(VectorNames))]
    public void EveryVectorMatches(string name)
    {
        var vector = LoadVectors().EnumerateArray().First(v => v.GetProperty("name").GetString() == name);

        long nowMs = DateTimeOffset.Parse(vector.GetProperty("now").GetString()!).ToUnixTimeMilliseconds();
        var opts = new WebhookVerifier.Options { NowMs = nowMs };

        var result = WebhookVerifier.Verify(
            vector.GetProperty("body").GetString()!,
            vector.GetProperty("signature").GetString(),
            vector.GetProperty("timestamp").GetString(),
            vector.GetProperty("secret").GetString()!,
            opts);

        bool expectedValid = vector.GetProperty("expected_valid").GetBoolean();
        Assert.True(expectedValid == result.Valid, $"vector {name}: {result.Reason}");
    }
}
