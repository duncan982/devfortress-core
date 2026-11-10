package net.devfortress;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BoundedMap (TODO 372), ported from
 * {@code packages/devfortress-sdk/src/internal-closed-loop-engine.ts}'s
 * generic, public BoundedMap. Distinct from the package-private
 * {@code net.devfortress.tier2gated.BoundedMap}.
 */
class BoundedMapTest {

    @Test
    void setAndGet() {
        BoundedMap<String, Integer> map = new BoundedMap<>(3);
        map.set("a", 1);
        assertEquals(1, map.get("a"));
    }

    @Test
    void getMissingKeyReturnsNull() {
        BoundedMap<String, Integer> map = new BoundedMap<>(3);
        assertNull(map.get("missing"));
    }

    @Test
    void evictsOldestOnceAtCapacity() {
        BoundedMap<String, Integer> map = new BoundedMap<>(2);
        map.set("a", 1);
        map.set("b", 2);
        map.set("c", 3);

        assertFalse(map.has("a"));
        assertTrue(map.has("b"));
        assertTrue(map.has("c"));
        assertEquals(2, map.size());
    }

    @Test
    void setOnExistingKeyDoesNotEvict() {
        BoundedMap<String, Integer> map = new BoundedMap<>(2);
        map.set("a", 1);
        map.set("b", 2);
        map.set("a", 99);

        assertEquals(2, map.size());
        assertEquals(99, map.get("a"));
    }

    @Test
    void deleteRemovesEntry() {
        BoundedMap<String, Integer> map = new BoundedMap<>(3);
        map.set("a", 1);

        assertTrue(map.delete("a"));
        assertFalse(map.has("a"));
        assertFalse(map.delete("a"));
    }

    @Test
    void clearRemovesAllEntries() {
        BoundedMap<String, Integer> map = new BoundedMap<>(3);
        map.set("a", 1);
        map.set("b", 2);
        map.clear();
        assertEquals(0, map.size());
    }

    @Test
    void forEachVisitsAllEntries() {
        BoundedMap<String, Integer> map = new BoundedMap<>(3);
        map.set("a", 1);
        map.set("b", 2);

        Map<String, Integer> seen = new HashMap<>();
        map.forEach(seen::put);

        assertEquals(Map.of("a", 1, "b", 2), seen);
    }
}
