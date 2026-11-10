namespace DevFortress;

/// <summary>
/// DevFortress SDK — Bounded Map. Mirrors
/// <c>packages/devfortress-sdk/src/internal-closed-loop-engine.ts</c>'s
/// generic, public <c>BoundedMap</c>.
///
/// <para>A bounded, LRU-ish map: once at capacity, <see cref="Set"/>
/// evicts the oldest-inserted entry still present. <see cref="Get"/>
/// does not change eviction order (eviction order is insertion order of
/// still-present keys, mirroring Node's Map-backed original, which
/// relies on the first key of <c>Map.keys()</c> for the oldest key, not
/// last-accessed).</para>
///
/// <para>Distinct from <c>DevFortress.Tier2Gated.BoundedMap</c>, a
/// separate, <c>internal</c> type used only by that namespace's gated
/// pillars — this is the new, public, top-level type with no namespace
/// collision.</para>
///
/// <para>Thread-safe.</para>
/// </summary>
public sealed class BoundedMap<TKey, TValue> where TKey : notnull
{
    private readonly object _lock = new();
    private readonly Dictionary<TKey, TValue> _store = new();
    private readonly List<TKey> _order = new();
    private readonly int _maxSize;

    public BoundedMap(int maxSize)
    {
        _maxSize = maxSize;
    }

    public TValue? Get(TKey key)
    {
        lock (_lock)
        {
            return _store.TryGetValue(key, out var v) ? v : default;
        }
    }

    public bool TryGet(TKey key, out TValue value)
    {
        lock (_lock)
        {
            return _store.TryGetValue(key, out value!);
        }
    }

    public void Set(TKey key, TValue value)
    {
        lock (_lock)
        {
            var existed = _store.ContainsKey(key);
            if (!existed && _store.Count >= _maxSize)
            {
                EvictOldest();
            }
            if (!existed)
            {
                _order.Add(key);
            }
            _store[key] = value;
        }
    }

    public bool Has(TKey key)
    {
        lock (_lock)
        {
            return _store.ContainsKey(key);
        }
    }

    public bool Delete(TKey key)
    {
        lock (_lock)
        {
            return _store.Remove(key);
        }
    }

    public int Size
    {
        get
        {
            lock (_lock)
            {
                return _store.Count;
            }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _store.Clear();
            _order.Clear();
        }
    }

    public List<TValue> Values()
    {
        lock (_lock)
        {
            return _store.Values.ToList();
        }
    }

    public List<TKey> Keys()
    {
        lock (_lock)
        {
            return _store.Keys.ToList();
        }
    }

    public void ForEach(Action<TKey, TValue> callback)
    {
        lock (_lock)
        {
            foreach (var (key, value) in _store)
            {
                callback(key, value);
            }
        }
    }

    private void EvictOldest()
    {
        while (_order.Count > 0)
        {
            var oldest = _order[0];
            _order.RemoveAt(0);
            if (_store.Remove(oldest))
            {
                return;
            }
        }
    }
}
