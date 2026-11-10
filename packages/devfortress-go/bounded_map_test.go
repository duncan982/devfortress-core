package devfortress

import "testing"

func TestBoundedMap_SetAndGet(t *testing.T) {
	m := NewBoundedMap[string, int](3)
	m.Set("a", 1)

	v, ok := m.Get("a")
	if !ok || v != 1 {
		t.Fatalf("expected a=1, got v=%d ok=%v", v, ok)
	}
}

func TestBoundedMap_GetMissingKeyReturnsFalse(t *testing.T) {
	m := NewBoundedMap[string, int](3)
	_, ok := m.Get("missing")
	if ok {
		t.Fatalf("expected ok=false for a missing key")
	}
}

func TestBoundedMap_EvictsOldestOnceAtCapacity(t *testing.T) {
	m := NewBoundedMap[string, int](2)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3) // evicts "a"

	if m.Has("a") {
		t.Fatalf("expected oldest key 'a' to be evicted")
	}
	if !m.Has("b") || !m.Has("c") {
		t.Fatalf("expected 'b' and 'c' to remain")
	}
	if m.Size() != 2 {
		t.Fatalf("expected size capped at 2, got %d", m.Size())
	}
}

func TestBoundedMap_SetOnExistingKeyDoesNotEvict(t *testing.T) {
	m := NewBoundedMap[string, int](2)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("a", 99) // update, not a new insertion

	if m.Size() != 2 {
		t.Fatalf("expected size to remain 2 after updating an existing key, got %d", m.Size())
	}
	v, _ := m.Get("a")
	if v != 99 {
		t.Fatalf("expected updated value 99, got %d", v)
	}
}

func TestBoundedMap_DeleteRemovesEntry(t *testing.T) {
	m := NewBoundedMap[string, int](3)
	m.Set("a", 1)

	if !m.Delete("a") {
		t.Fatalf("expected Delete to report true for an existing key")
	}
	if m.Has("a") {
		t.Fatalf("expected 'a' to be gone after Delete")
	}
	if m.Delete("a") {
		t.Fatalf("expected a second Delete to report false")
	}
}

func TestBoundedMap_ClearRemovesAllEntries(t *testing.T) {
	m := NewBoundedMap[string, int](3)
	m.Set("a", 1)
	m.Set("b", 2)

	m.Clear()
	if m.Size() != 0 {
		t.Fatalf("expected size 0 after Clear, got %d", m.Size())
	}
}

func TestBoundedMap_ForEachVisitsAllEntries(t *testing.T) {
	m := NewBoundedMap[string, int](3)
	m.Set("a", 1)
	m.Set("b", 2)

	seen := map[string]int{}
	m.ForEach(func(key string, value int) {
		seen[key] = value
	})

	if len(seen) != 2 || seen["a"] != 1 || seen["b"] != 2 {
		t.Fatalf("expected ForEach to visit both entries, got %v", seen)
	}
}
