# frozen_string_literal: true

require "openssl"
require "digest"
require "json"
require "securerandom"

module DevFortress
  # Credential Isolation Security — Session Indirection (Hardened)
  #
  # Replaces real session tokens with opaque, random aliases before they
  # leave the client app's trust boundary. DevFortress only ever sees the
  # alias — never the real token. Mirrors
  # packages/devfortress-sdk/src/credential-isolation.ts (IP-M3 through
  # IP-M7, IP-S5).
  #
  # A cache adapter is any object responding to #get(key), #set(key, value,
  # ttl_seconds) and #del(key); falls back to an in-memory store for
  # development/testing. For production use with Redis, implement this
  # duck type against your Redis client.

  # In-memory LRU cache (IP-S5) — fallback for Redis.
  class LRUCache
    def initialize(max_entries = 1000, default_ttl_seconds = 60)
      @max_entries = max_entries
      @default_ttl = default_ttl_seconds
      @cache = {}
    end

    def get(key)
      entry = @cache[key]
      return nil unless entry
      if Time.now.to_f > entry[:expires_at]
        @cache.delete(key)
        return nil
      end
      # Move to end (most recently used)
      @cache.delete(key)
      @cache[key] = entry
      entry[:value]
    end

    def set(key, value, ttl_seconds = nil)
      if @cache.size >= @max_entries && !@cache.key?(key)
        @cache.delete(@cache.first[0])
      end
      @cache[key] = { value: value, expires_at: Time.now.to_f + (ttl_seconds || @default_ttl) }
    end

    def del(key)
      @cache.delete(key)
    end

    def has?(key)
      !get(key).nil?
    end
  end

  # In-memory cache adapter (development fallback), shared process-wide —
  # mirrors the Node SDK's module-level memStore.
  class MemoryCacheAdapter
    def initialize
      @mutex = Mutex.new
      @store = {}
    end

    def get(key)
      @mutex.synchronize do
        entry = @store[key]
        return nil unless entry
        if Time.now.to_f > entry[:expires_at]
          @store.delete(key)
          return nil
        end
        entry[:value]
      end
    end

    def set(key, value, ttl_seconds)
      @mutex.synchronize { @store[key] = { value: value, expires_at: Time.now.to_f + ttl_seconds } }
    end

    def del(key)
      @mutex.synchronize { @store.delete(key) }
    end
  end

  DEFAULT_MEMORY_ADAPTER = MemoryCacheAdapter.new
  private_constant :DEFAULT_MEMORY_ADAPTER

  # Local emergency blocklist (IP-M6) — synchronous, pre-webhook IP
  # blocking. When a critical event fires, the IP is written here BEFORE
  # the webhook is sent, so the IP is blocked even if the webhook receiver
  # is down.
  class ThreatInterceptor
    # Default TTL: 15 minutes (10 min webhook retry window + 5 min safety)
    def initialize(cache: nil, ttl_seconds: 900)
      @cache = cache || DEFAULT_MEMORY_ADAPTER
      @lru = LRUCache.new(5000, ttl_seconds)
      @default_ttl_seconds = ttl_seconds
    end

    def block_ip(ip, reason: "critical_event")
      value = JSON.generate({ reason: reason, blocked_at: (Time.now.to_f * 1000).to_i })
      @lru.set("emergency:block:#{ip}", value, @default_ttl_seconds)
      begin
        @cache.set("emergency:block:#{ip}", value, @default_ttl_seconds)
      rescue StandardError
        # LRU cache is already set — cache failure doesn't prevent blocking
      end
    end

    def blocked?(ip)
      return true if @lru.has?("emergency:block:#{ip}")

      begin
        !@cache.get("emergency:block:#{ip}").nil?
      rescue StandardError
        false # On cache failure, LRU was already checked
      end
    end

    def unblock_ip(ip)
      @lru.del("emergency:block:#{ip}")
      begin
        @cache.del("emergency:block:#{ip}")
      rescue StandardError
        # Best-effort
      end
    end
  end

  REVOCATION_REASONS = %w[active_threat rotation_expired logout].freeze

  # Credential Isolation Manager (Hardened).
  class CredentialIsolationManager
    def initialize(cache_adapter: nil, encryption_key: nil, lru_max_entries: 1000, lru_ttl_seconds: 60,
                    rotation_grace_period_seconds: 1200, on_fallback_revocation: nil)
      @cache = cache_adapter || DEFAULT_MEMORY_ADAPTER
      @lru = LRUCache.new(lru_max_entries, lru_ttl_seconds)
      @rotation_grace_period = rotation_grace_period_seconds
      @on_fallback_revocation = on_fallback_revocation

      # Encryption is mandatory: credentials must never be cached in
      # plaintext. Fail loudly at construction time rather than silently
      # no-op'ing in #encrypt_value/#decrypt_value.
      key = encryption_key || ENV["DEVFORTRESS_REDIS_ENCRYPTION_KEY"]
      if key.nil? || key.empty?
        raise ArgumentError,
              "DEVFORTRESS_REDIS_ENCRYPTION_KEY is required — CredentialIsolationManager refuses to store " \
              "credentials without encryption. Set this env var to a 32-byte hex string (64 hex characters), " \
              "e.g. `openssl rand -hex 32`, or pass encryption_key: explicitly."
      end
      if key.length != 64
        raise ArgumentError, "DEVFORTRESS_REDIS_ENCRYPTION_KEY must be a 32-byte hex string (64 hex characters)"
      end

      @encryption_key = key
    end

    ENCRYPTED_PREFIX = "enc:v1:"

    # Generate a cryptographically random alias for a real session token.
    # The alias has NO mathematical relationship to the real token.
    def create_alias(real_token, user_id, ttl_seconds: 3600)
      token_hash = hash_token(real_token)

      existing_alias = cache_get("cred:alias:#{token_hash}")
      return existing_alias if existing_alias

      alias_id = "df_sid_#{SecureRandom.hex(16)}"
      data = { "realToken" => real_token, "userId" => user_id, "createdAt" => now_ms }

      encrypted_data = encrypt_value(JSON.generate(data))
      cache_set("alias:#{alias_id}", encrypted_data, ttl_seconds)
      cache_set("cred:alias:#{token_hash}", alias_id, ttl_seconds)

      alias_id
    end

    # Resolve an alias back to the real token and user. Called ONLY when a
    # revocation webhook arrives from DevFortress.
    def resolve_alias(alias_id)
      raw = cache_get("alias:#{alias_id}")
      return nil unless raw

      begin
        decrypted = decrypt_value(raw)
        data = JSON.parse(decrypted)
        { "realToken" => data["realToken"], "userId" => data["userId"], "createdAt" => data["createdAt"] }
      rescue StandardError
        nil
      end
    end

    # Revoke a session by alias. The real token is resolved within the
    # client app — DevFortress never touches the real token.
    def revoke_by_alias(alias_id, reason: "active_threat", subject_id: nil)
      resolved = resolve_alias(alias_id)
      if resolved.nil?
        if subject_id && @on_fallback_revocation
          @on_fallback_revocation.call(subject_id, "[DF] alias resolution failed for #{alias_id} — falling back to subjectId revocation")
        end
        return nil
      end

      token_hash = hash_token(resolved["realToken"])
      cache_del("alias:#{alias_id}")
      cache_del("cred:alias:#{token_hash}")

      marker = JSON.generate({ "revoked" => true, "reason" => reason, "revokedAt" => now_ms, "revocation_scope" => "precise" })
      cache_set("revoked:alias:#{alias_id}", marker, 86_400)

      resolved
    rescue StandardError => e
      fallback_subject = subject_id || "unknown"
      @on_fallback_revocation&.call(fallback_subject, "[DF] cache error during revoke_by_alias(#{alias_id}) — falling back to subjectId revocation. Error: #{e.message}")
      begin
        marker = JSON.generate({ "revoked" => true, "reason" => reason, "revokedAt" => now_ms, "revocation_scope" => "broad" })
        cache_set("revoked:alias:#{alias_id}", marker, 86_400)
      rescue StandardError
        # Best-effort
      end
      nil
    end

    # Rotate alias — replaces the alias for a live session. IP-M7: the old
    # alias is NOT deleted immediately; it gets a grace-period TTL and stays
    # resolvable for revocation purposes.
    def rotate_alias(old_alias, ttl_seconds: 3600)
      resolved = resolve_alias(old_alias)
      return nil unless resolved

      rotating_data = resolved.merge("status" => "rotating", "canCreateNewEvents" => false)
      encrypted_rotating = encrypt_value(JSON.generate(rotating_data))
      cache_set("alias:#{old_alias}", encrypted_rotating, @rotation_grace_period)

      token_hash = hash_token(resolved["realToken"])
      cache_del("cred:alias:#{token_hash}")

      create_alias(resolved["realToken"], resolved["userId"], ttl_seconds: ttl_seconds)
    end

    # Clean up alias when user logs out normally. Always call this on
    # logout — don't wait for TTL expiry.
    def revoke_on_logout(real_token)
      token_hash = hash_token(real_token)
      alias_id = cache_get("cred:alias:#{token_hash}")
      return unless alias_id

      marker = JSON.generate({ "revoked" => true, "reason" => "logout", "revokedAt" => now_ms, "revocation_scope" => "precise" })
      cache_set("revoked:alias:#{alias_id}", marker, 86_400)
      cache_del("alias:#{alias_id}")
      cache_del("cred:alias:#{token_hash}")
    end

    # Check if an alias was already revoked (idempotency for webhook retries).
    def revoked?(alias_id)
      !cache_get("revoked:alias:#{alias_id}").nil?
    end

    def revocation_details(alias_id)
      raw = cache_get("revoked:alias:#{alias_id}")
      return nil unless raw

      begin
        JSON.parse(raw)
      rescue JSON::ParserError
        { "reason" => "active_threat", "revokedAt" => now_ms, "revocation_scope" => "precise" }
      end
    end

    private

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    def encrypt_value(plaintext)
      key = [@encryption_key].pack("H*")
      iv = SecureRandom.random_bytes(12)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      encrypted = cipher.update(plaintext) + cipher.final
      "#{ENCRYPTED_PREFIX}#{iv.unpack1('H*')}:#{encrypted.unpack1('H*')}:#{cipher.auth_tag.unpack1('H*')}"
    end

    def decrypt_value(ciphertext)
      return ciphertext unless ciphertext.start_with?(ENCRYPTED_PREFIX)

      parts = ciphertext[ENCRYPTED_PREFIX.length..].split(":")
      raise "Invalid encrypted format" unless parts.length == 3

      key = [@encryption_key].pack("H*")
      decipher = OpenSSL::Cipher.new("aes-256-gcm")
      decipher.decrypt
      decipher.key = key
      decipher.iv = [parts[0]].pack("H*")
      decipher.auth_tag = [parts[2]].pack("H*")
      decipher.update([parts[1]].pack("H*")) + decipher.final
    end

    def hash_token(real_token)
      Digest::SHA256.hexdigest(real_token)
    end

    def cache_get(key)
      begin
        value = @cache.get(key)
        if !value.nil?
          @lru.set(key)
          return value
        end
      rescue StandardError
        # Cache failure — fall back to LRU (IP-S5)
      end
      @lru.get(key)
    end

    def cache_set(key, value, ttl_seconds)
      @lru.set(key, value, ttl_seconds)
      begin
        @cache.set(key, value, ttl_seconds)
      rescue StandardError
        # LRU is set — cache failure is survivable
      end
    end

    def cache_del(key)
      @lru.del(key)
      begin
        @cache.del(key)
      rescue StandardError
        # Best-effort
      end
    end
  end
end
