# frozen_string_literal: true

module DevFortress
  # Bounded Map.
  #
  # Mirrors packages/devfortress-sdk/src/internal-closed-loop-engine.ts's
  # generic, public BoundedMap. A bounded, LRU-ish map: once at
  # capacity, Set evicts the oldest-inserted entry still present. Get
  # does not change eviction order (eviction order is insertion order
  # of still-present keys, mirroring Node's Map-backed original, which
  # relies on Map#keys.first for the oldest key, not last-accessed).
  # Safe for concurrent use.
  class BoundedMap
    def initialize(max_size)
      @max_size = max_size
      @store = {}
      @order = []
      @mutex = Mutex.new
    end

    def get(key)
      @mutex.synchronize { @store[key] }
    end

    def set(key, value)
      @mutex.synchronize do
        existed = @store.key?(key)
        evict_oldest if !existed && @store.size >= @max_size
        @order << key unless existed
        @store[key] = value
      end
    end

    def has?(key)
      @mutex.synchronize { @store.key?(key) }
    end

    def delete(key)
      @mutex.synchronize do
        existed = @store.key?(key)
        @store.delete(key)
        existed
      end
    end

    def size
      @mutex.synchronize { @store.size }
    end

    def clear
      @mutex.synchronize do
        @store = {}
        @order = []
      end
    end

    def values
      @mutex.synchronize { @store.values }
    end

    def keys
      @mutex.synchronize { @store.keys }
    end

    def each(&block)
      @mutex.synchronize { @store.each(&block) }
    end

    private

    def evict_oldest
      while (oldest = @order.shift)
        if @store.key?(oldest)
          @store.delete(oldest)
          return
        end
      end
    end
  end
end
