package net.devfortress;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * DevFortress SDK — Bounded Map. Mirrors
 * {@code packages/devfortress-sdk/src/internal-closed-loop-engine.ts}'s
 * generic, public {@code BoundedMap}.
 *
 * <p>A bounded, LRU-ish map: once at capacity, {@link #set} evicts the
 * oldest-inserted entry still present. {@link #get} does not change
 * eviction order (eviction order is insertion order of still-present
 * keys, mirroring Node's Map-backed original, which relies on the
 * first key of {@code Map.keys()} for the oldest key, not
 * last-accessed).
 *
 * <p>Distinct from {@code net.devfortress.tier2gated.BoundedMap}, a
 * separate, package-private type used only by that package's gated
 * pillars — this is the new, public, top-level type with no namespace
 * collision.
 *
 * <p>Safe for concurrent use.
 *
 * @param <K> key type
 * @param <V> value type
 */
public final class BoundedMap<K, V> {

    private final Object lock = new Object();
    private final Map<K, V> store = new HashMap<>();
    private final List<K> order = new ArrayList<>();
    private final int maxSize;

    public BoundedMap(int maxSize) {
        this.maxSize = maxSize;
    }

    public V get(K key) {
        synchronized (lock) {
            return store.get(key);
        }
    }

    public void set(K key, V value) {
        synchronized (lock) {
            boolean existed = store.containsKey(key);
            if (!existed && store.size() >= maxSize) {
                evictOldest();
            }
            if (!existed) {
                order.add(key);
            }
            store.put(key, value);
        }
    }

    public boolean has(K key) {
        synchronized (lock) {
            return store.containsKey(key);
        }
    }

    public boolean delete(K key) {
        synchronized (lock) {
            boolean existed = store.containsKey(key);
            store.remove(key);
            return existed;
        }
    }

    public int size() {
        synchronized (lock) {
            return store.size();
        }
    }

    public void clear() {
        synchronized (lock) {
            store.clear();
            order.clear();
        }
    }

    public List<V> values() {
        synchronized (lock) {
            return new ArrayList<>(store.values());
        }
    }

    public List<K> keys() {
        synchronized (lock) {
            return new ArrayList<>(store.keySet());
        }
    }

    public void forEach(BiConsumer<K, V> callback) {
        synchronized (lock) {
            store.forEach(callback);
        }
    }

    private void evictOldest() {
        while (!order.isEmpty()) {
            K oldest = order.remove(0);
            if (store.remove(oldest) != null) {
                return;
            }
        }
    }
}
