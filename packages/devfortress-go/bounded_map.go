package devfortress

import "sync"

// ── BoundedMap ────────────────────────────────────────────────────────────

// Mirrors the Node SDK's generic, public BoundedMap
// (internal-closed-loop-engine.ts). A bounded, LRU-ish map: on Set,
// once the map is at capacity, the oldest-inserted entry still present
// is evicted. Get does not change eviction order (eviction order is
// insertion order of the still-present keys, mirroring Node's
// Map-backed original, which relies on Map.keys().next().value for the
// oldest key — not last-accessed). Safe for concurrent use.
type BoundedMap[K comparable, V any] struct {
	mu      sync.Mutex
	store   map[K]V
	order   []K
	maxSize int
}

// NewBoundedMap creates a BoundedMap capped at maxSize entries.
func NewBoundedMap[K comparable, V any](maxSize int) *BoundedMap[K, V] {
	return &BoundedMap[K, V]{
		store:   make(map[K]V),
		maxSize: maxSize,
	}
}

// Get returns the value for key, and whether it was present.
func (m *BoundedMap[K, V]) Get(key K) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.store[key]
	return v, ok
}

// Set stores value under key, evicting the oldest entry if the map is
// at capacity and key is new.
func (m *BoundedMap[K, V]) Set(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.store[key]; !exists && len(m.store) >= m.maxSize {
		m.evictOldest()
	}
	if _, exists := m.store[key]; !exists {
		m.order = append(m.order, key)
	}
	m.store[key] = value
}

// Has reports whether key is present.
func (m *BoundedMap[K, V]) Has(key K) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.store[key]
	return ok
}

// Delete removes key, reporting whether it was present.
func (m *BoundedMap[K, V]) Delete(key K) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.store[key]
	delete(m.store, key)
	return ok
}

// Size returns the number of entries currently stored.
func (m *BoundedMap[K, V]) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.store)
}

// Clear removes all entries.
func (m *BoundedMap[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = make(map[K]V)
	m.order = nil
}

// Values returns a snapshot slice of all stored values.
func (m *BoundedMap[K, V]) Values() []V {
	m.mu.Lock()
	defer m.mu.Unlock()
	values := make([]V, 0, len(m.store))
	for _, v := range m.store {
		values = append(values, v)
	}
	return values
}

// Keys returns a snapshot slice of all stored keys.
func (m *BoundedMap[K, V]) Keys() []K {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]K, 0, len(m.store))
	for k := range m.store {
		keys = append(keys, k)
	}
	return keys
}

// ForEach calls fn for every stored entry.
func (m *BoundedMap[K, V]) ForEach(fn func(key K, value V)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.store {
		fn(k, v)
	}
}

// evictOldest removes the oldest-inserted key still present. Caller
// must hold m.mu.
func (m *BoundedMap[K, V]) evictOldest() {
	for len(m.order) > 0 {
		oldest := m.order[0]
		m.order = m.order[1:]
		if _, ok := m.store[oldest]; ok {
			delete(m.store, oldest)
			return
		}
	}
}
