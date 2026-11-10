# frozen_string_literal: true

require "digest"
require "securerandom"
require_relative "credential_vault"

module DevFortress
  # API Key Aliasing Service (Invention A19).
  # Patent Pending — KIPI KE/P/2026/005972
  # Prior art: https://www.tdcommons.org/dpubs_series/9907/
  #
  # Mirrors packages/devfortress-sdk/src/api-key-aliasing.ts. Provides
  # alias lifecycle management for API keys: create, rotate, revoke,
  # inspect, and audit. Each alias is scoped to a workload (CI, agent,
  # browser, server) with fingerprint and scope binding.
  AliasRecord = Struct.new(
    :alias_id, :alias_key, :primary_key_hash, :workload, :label, :state,
    :fingerprint, :scope, :created_at, :expires_at, :last_used_at,
    :rotated_from_id, :rotated_to_id, :usage_count, keyword_init: true,
  )

  AliasAuditEvent = Struct.new(:type, :alias_id, :primary_key_hash, :workload, :timestamp, :metadata, keyword_init: true)

  WORKLOADS = %w[ci agent plugin browser server custom].freeze

  class APIKeyAliasingService
    def initialize(max_aliases_per_key: 50, rotation_overlap_ms: 300_000, max_primary_keys: 10_000,
                    anomaly_detection: true, creation_burst_threshold: 10, vault_secret: nil, debug: false)
      @max_aliases_per_key = max_aliases_per_key
      @rotation_overlap_ms = rotation_overlap_ms
      @max_primary_keys = max_primary_keys
      @anomaly_detection = anomaly_detection
      @creation_burst_threshold = creation_burst_threshold
      @debug = debug

      @aliases = {}
      @alias_key_index = {}
      @primary_key_aliases = {}
      @audit_log = []
      @creation_timestamps = []

      @vault_key = vault_secret ? CredentialVault.derive_vault_key(vault_secret, "api-key-aliasing") : SecureRandom.random_bytes(32)
    end

    # Create a new alias for a primary API key.
    def create_alias(primary_key_hash, workload, label, fingerprint: nil, scope: nil, expires_in_ms: nil)
      now = now_ms

      existing = @primary_key_aliases[primary_key_hash]
      if existing && existing.size >= @max_aliases_per_key
        return { success: false, error: "Maximum aliases (#{@max_aliases_per_key}) reached for this key" }
      end

      if @anomaly_detection
        @creation_timestamps << now
        recent_creations = @creation_timestamps.select { |t| now - t <= 3_600_000 }
        if recent_creations.length > @creation_burst_threshold
          emit_audit(type: "alias_misuse_detected", alias_id: "N/A", primary_key_hash: primary_key_hash,
                     workload: workload, timestamp: now, metadata: { reason: "creation_burst", count: recent_creations.length })
          return { success: false, error: "Alias creation burst detected: #{recent_creations.length} in 1 hour" }
        end
      end

      alias_id = "alias_#{SecureRandom.hex(16)}"
      alias_key = "vx_alias_#{SecureRandom.hex(24)}"
      alias_key_hash = Digest::SHA256.hexdigest(alias_key)

      record = AliasRecord.new(
        alias_id: alias_id, alias_key: encrypt_alias_key(alias_key, primary_key_hash),
        primary_key_hash: primary_key_hash, workload: workload, label: label, state: "active",
        fingerprint: fingerprint, scope: scope, created_at: now,
        expires_at: expires_in_ms ? now + expires_in_ms : nil, last_used_at: now, usage_count: 0,
      )

      @aliases[alias_id] = record
      @alias_key_index[alias_key_hash] = alias_id
      (@primary_key_aliases[primary_key_hash] ||= []) << alias_id

      emit_audit(type: "alias_created", alias_id: alias_id, primary_key_hash: primary_key_hash, workload: workload,
                 timestamp: now, metadata: { label: label, has_fingerprint: !fingerprint.nil?, scope: scope })

      redacted = record.dup
      redacted.alias_key = "[REDACTED]"
      { success: true, alias: redacted, alias_key: alias_key }
    end

    # Rotate an alias with zero-downtime overlap window.
    def rotate_alias(alias_id)
      now = now_ms
      old_alias = @aliases[alias_id]
      return { success: false, error: "Alias #{alias_id} not found or not active" } if !old_alias || old_alias.state != "active"

      old_alias.state = "rotating"
      old_alias.expires_at = now + @rotation_overlap_ms

      result = create_alias(old_alias.primary_key_hash, old_alias.workload, "#{old_alias.label} (rotated)",
                             fingerprint: old_alias.fingerprint, scope: old_alias.scope)

      unless result[:success] && result[:alias]
        old_alias.state = "active" # Rollback
        return { success: false, error: result[:error] }
      end

      old_alias.rotated_to_id = result[:alias].alias_id
      result[:alias].rotated_from_id = alias_id

      emit_audit(type: "alias_rotated", alias_id: alias_id, primary_key_hash: old_alias.primary_key_hash,
                 workload: old_alias.workload, timestamp: now,
                 metadata: { new_alias_id: result[:alias].alias_id, overlap_ms: @rotation_overlap_ms })

      { success: true, old_alias_id: alias_id, new_alias: result[:alias], new_alias_key: result[:alias_key],
        overlap_expires_at: old_alias.expires_at }
    end

    # Revoke a specific alias without affecting other aliases.
    def revoke_alias(alias_id, reason: nil)
      alias_record = @aliases[alias_id]
      return false unless alias_record

      alias_record.state = "revoked"
      emit_audit(type: "alias_revoked", alias_id: alias_id, primary_key_hash: alias_record.primary_key_hash,
                 workload: alias_record.workload, timestamp: now_ms, metadata: { reason: reason || "manual_revocation" })
      true
    end

    # Validate an alias key for incoming requests.
    def validate_alias_key(alias_key, fingerprint: nil)
      alias_key_hash = Digest::SHA256.hexdigest(alias_key)
      alias_id = @alias_key_index[alias_key_hash]
      return { valid: false, reason: "Unknown alias key" } unless alias_id

      alias_record = @aliases[alias_id]
      return { valid: false, reason: "Alias record not found" } unless alias_record

      now = now_ms

      if alias_record.state == "revoked"
        return { valid: false, alias_id: alias_id, workload: alias_record.workload, reason: "Alias has been revoked" }
      end

      if alias_record.expires_at && now > alias_record.expires_at
        alias_record.state = "expired"
        emit_audit(type: "alias_expired", alias_id: alias_id, primary_key_hash: alias_record.primary_key_hash,
                   workload: alias_record.workload, timestamp: now)
        return { valid: false, alias_id: alias_id, workload: alias_record.workload, reason: "Alias has expired" }
      end

      anomaly_detected = false
      if alias_record.fingerprint && fingerprint && alias_record.fingerprint != fingerprint
        anomaly_detected = true
        emit_audit(type: "alias_misuse_detected", alias_id: alias_id, primary_key_hash: alias_record.primary_key_hash,
                   workload: alias_record.workload, timestamp: now,
                   metadata: { reason: "fingerprint_mismatch", expected_fingerprint: alias_record.fingerprint[0, 8] })
      end

      alias_record.last_used_at = now
      alias_record.usage_count += 1

      emit_audit(type: "alias_used", alias_id: alias_id, primary_key_hash: alias_record.primary_key_hash,
                 workload: alias_record.workload, timestamp: now)

      {
        valid: !anomaly_detected, alias_id: alias_id, workload: alias_record.workload,
        primary_key_hash: alias_record.primary_key_hash,
        reason: anomaly_detected ? "Fingerprint mismatch detected" : "Valid alias",
        anomaly_detected: anomaly_detected,
      }
    end

    # List all aliases for a primary key.
    def list_aliases(primary_key_hash)
      alias_ids = @primary_key_aliases[primary_key_hash]
      return [] unless alias_ids

      alias_ids.filter_map { |id| @aliases[id] }.map do |a|
        redacted = a.dup
        redacted.alias_key = "[REDACTED]"
        redacted
      end
    end

    def stats
      result = {
        total_aliases: @aliases.size, active_aliases: 0, rotating_aliases: 0, revoked_aliases: 0,
        by_workload: WORKLOADS.to_h { |w| [w, 0] }, recent_anomalies: 0,
      }

      @aliases.each_value do |a|
        case a.state
        when "active" then result[:active_aliases] += 1
        when "rotating" then result[:rotating_aliases] += 1
        when "revoked" then result[:revoked_aliases] += 1
        end
        result[:by_workload][a.workload] += 1
      end

      one_hour_ago = now_ms - 3_600_000
      result[:recent_anomalies] = @audit_log.count { |e| e.type == "alias_misuse_detected" && e.timestamp > one_hour_ago }
      result
    end

    def audit_log(limit = 100)
      @audit_log.last(limit)
    end

    # Resolve a stored alias back to its real alias key. Returns nil for
    # an unknown/revoked/expired alias, or if the stored ciphertext fails
    # auth-tag verification (tampered/corrupted).
    def resolve(alias_id)
      alias_record = @aliases[alias_id]
      return nil unless alias_record
      return nil if %w[revoked expired].include?(alias_record.state)

      decrypted = CredentialVault.decrypt(alias_record.alias_key, @vault_key)
      separator_index = decrypted.index(":")
      separator_index.nil? ? decrypted : decrypted[(separator_index + 1)..]
    rescue StandardError
      nil
    end

    private

    # AES-256-GCM encrypt the alias key for forward-map storage.
    def encrypt_alias_key(alias_key, primary_key_hash)
      CredentialVault.encrypt("#{primary_key_hash}:#{alias_key}", @vault_key)
    end

    def emit_audit(type:, alias_id:, primary_key_hash:, workload:, timestamp:, metadata: nil)
      event = AliasAuditEvent.new(type: type, alias_id: alias_id, primary_key_hash: primary_key_hash,
                                   workload: workload, timestamp: timestamp, metadata: metadata)
      @audit_log << event
      @audit_log.shift(@audit_log.length - 10_000) if @audit_log.length > 10_000
      warn "[A19-Alias] #{type}: #{alias_id} (#{workload})" if @debug
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end
  end
end
