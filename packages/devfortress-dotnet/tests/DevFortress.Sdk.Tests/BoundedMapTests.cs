using DevFortress;
using Xunit;

namespace DevFortress.Sdk.Tests;

/// <summary>
/// BoundedMap (TODO 372), ported from
/// <c>packages/devfortress-sdk/src/internal-closed-loop-engine.ts</c>'s
/// generic, public BoundedMap. Distinct from the internal
/// <c>DevFortress.Tier2Gated.BoundedMap</c>.
/// </summary>
public class BoundedMapTests
{
    [Fact]
    public void SetAndGet_ReturnsStoredValue()
    {
        var map = new BoundedMap<string, int>(3);
        map.Set("a", 1);
        Assert.Equal(1, map.Get("a"));
    }

    [Fact]
    public void Get_MissingKey_ReturnsDefault()
    {
        var map = new BoundedMap<string, int>(3);
        Assert.Equal(0, map.Get("missing"));
        Assert.False(map.TryGet("missing", out _));
    }

    [Fact]
    public void Set_AtCapacity_EvictsOldestOnce()
    {
        var map = new BoundedMap<string, int>(2);
        map.Set("a", 1);
        map.Set("b", 2);
        map.Set("c", 3);

        Assert.False(map.Has("a"));
        Assert.True(map.Has("b"));
        Assert.True(map.Has("c"));
        Assert.Equal(2, map.Size);
    }

    [Fact]
    public void Set_OnExistingKey_DoesNotEvict()
    {
        var map = new BoundedMap<string, int>(2);
        map.Set("a", 1);
        map.Set("b", 2);
        map.Set("a", 99);

        Assert.Equal(2, map.Size);
        Assert.Equal(99, map.Get("a"));
    }

    [Fact]
    public void Delete_RemovesEntry()
    {
        var map = new BoundedMap<string, int>(3);
        map.Set("a", 1);

        Assert.True(map.Delete("a"));
        Assert.False(map.Has("a"));
        Assert.False(map.Delete("a"));
    }

    [Fact]
    public void Clear_RemovesAllEntries()
    {
        var map = new BoundedMap<string, int>(3);
        map.Set("a", 1);
        map.Set("b", 2);
        map.Clear();
        Assert.Equal(0, map.Size);
    }

    [Fact]
    public void ForEach_VisitsAllEntries()
    {
        var map = new BoundedMap<string, int>(3);
        map.Set("a", 1);
        map.Set("b", 2);

        var seen = new Dictionary<string, int>();
        map.ForEach((key, value) => seen[key] = value);

        Assert.Equal(new Dictionary<string, int> { ["a"] = 1, ["b"] = 2 }, seen);
    }
}
