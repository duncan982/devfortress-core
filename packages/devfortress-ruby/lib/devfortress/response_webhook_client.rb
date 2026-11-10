# frozen_string_literal: true

require "openssl"
require "json"
require "time"
require_relative "transport"
require_relative "webhook_verifier"
require_relative "credential_isolation" # LRUCache

module DevFortress
  # Delivers closed-loop response commands (session revocation, IP block)
  # to a single customer-configured webhook endpoint — the outbound
  # direction of the closed loop, complementing WebhookVerifier.verify
  # (the inbound direction: verifying a command the platform sent to this
  # application). Every delivery is HMAC-SHA256 signed the same way
  # WebhookVerifier checks it (hex HMAC over "{timestamp}.{body}"), rate
  # limited per endpoint (60/min, S28 webhook flooding protection), and
  # awaited with a short SLA timeout. Mirrors the outbound-delivery half of
  # packages/devfortress-sdk/src/devfortress.ts (deliverSessionRevocation /
  # deliverIPBlock / checkWebhookRateLimit).
  class ResponseWebhookClient
    RATE_WINDOW_SECONDS = 60
    RATE_LIMIT = 60
    BLOCK_CACHE_MAX_ENTRIES = 10_000
    DEFAULT_BLOCK_CACHE_TTL_SECONDS = 3600

    def initialize(url, secret, transport: nil)
      @url = url
      @secret = secret
      @transport = transport || Transport.new
      @mutex = Mutex.new
      @buckets = {}
      @block_cache = LRUCache.new(BLOCK_CACHE_MAX_ENTRIES, DEFAULT_BLOCK_CACHE_TTL_SECONDS)
    end

    # Reports whether ip was locally cached as blocked by a prior
    # #record_inbound_command call — local-only, no network call. Mirrors
    # Node's own external-mode isBlocked()/memGet pair and Python's
    # ClosedLoopEngine#is_blocked_ip (TODO 358): this SDK previously
    # delivered and verified block/revocation commands but never
    # self-enforced them locally, leaving every embedding app to implement
    # its own cache.
    def ip_blocked?(ip)
      @mutex.synchronize { @block_cache.has?("blocked:ip:#{ip}") }
    end

    # Reports whether user_id was locally cached as blocked by a prior
    # #record_inbound_command call — local-only, no network call.
    def user_blocked?(user_id)
      @mutex.synchronize { @block_cache.has?("blocked:user:#{user_id}") }
    end

    # Locally caches the block/revocation decision carried by an
    # already-verified inbound command (see WebhookVerifier.verify +
    # WebhookCommand.parse), so a subsequent #ip_blocked?/#user_blocked?
    # call enforces it without a remote round-trip.
    #
    # An "ip_block" command is cached only when its severity is "critical"
    # or "high" (or unset — #deliver_ip_block defaults to "high" when the
    # sender leaves it empty), matching Node/Python's own severity gate. A
    # "session_revocation" command carries no severity field on this SDK's
    # wire shape (see #deliver_session_revocation's body) — its delivery
    # already represents a decided enforcement action, so it is always
    # cached.
    def record_inbound_command(command)
      ttl_seconds = command["ttl_seconds"] || DEFAULT_BLOCK_CACHE_TTL_SECONDS

      case command["type"]
      when "ip_block"
        severity = command["severity"]
        return if severity && !%w[high critical].include?(severity)

        ip = command["ip"]
        cache_block("blocked:ip:#{ip}", ttl_seconds) if ip && !ip.empty?
      when "session_revocation"
        user_id = command["user_id"]
        ip = command["ip"]
        cache_block("blocked:user:#{user_id}", ttl_seconds) if user_id && !user_id.empty?
        cache_block("blocked:ip:#{ip}", ttl_seconds) if ip && !ip.empty?
      end
    end

    # Deliver a session-revocation command, awaiting acknowledgement with
    # a 2-second SLA timeout.
    def deliver_session_revocation(session_id:, user_id: nil, reason:, ip: nil)
      return { delivered: false } if @url.nil? || @url.empty? || @secret.nil? || @secret.empty?
      return { delivered: false } unless check_rate_limit(@url)

      timestamp = now_iso
      body = JSON.generate({
        "type" => "session_revocation", "session_id" => session_id, "user_id" => user_id,
        "reason" => reason, "ip" => ip, "issued_at" => timestamp,
      })
      deliver(timestamp, body, 2)
    end

    # Deliver an IP-block command so the customer can enforce at the edge
    # (CDN/WAF/load balancer), awaiting acknowledgement with a 5-second
    # SLA timeout.
    def deliver_ip_block(ip:, reason:, ttl_seconds: 3600, severity: "high")
      return { delivered: false } if @url.nil? || @url.empty? || @secret.nil? || @secret.empty?
      return { delivered: false } unless check_rate_limit(@url)

      timestamp = now_iso
      body = JSON.generate({
        "type" => "ip_block", "ip" => ip, "reason" => reason, "ttl_seconds" => ttl_seconds,
        "severity" => severity, "issued_at" => timestamp,
      })
      deliver(timestamp, body, 5)
    end

    private

    def cache_block(key, ttl_seconds)
      @mutex.synchronize { @block_cache.set(key, "1", ttl_seconds) }
    end

    def deliver(timestamp, body, timeout_seconds)
      signature = OpenSSL::HMAC.hexdigest("SHA256", @secret, "#{timestamp}.#{body}")
      headers = {
        "Content-Type" => "application/json",
        WebhookVerifier::SIGNATURE_HEADER => signature,
        WebhookVerifier::TIMESTAMP_HEADER => timestamp,
      }
      start = Time.now
      begin
        @transport.send_request("POST", @url, headers, body, timeout_seconds)
        { delivered: true, ack_time_seconds: Time.now - start }
      rescue TransportError
        { delivered: false, ack_time_seconds: Time.now - start }
      end
    end

    # S28 webhook flooding protection: at most RATE_LIMIT deliveries per
    # endpoint per RATE_WINDOW_SECONDS.
    def check_rate_limit(endpoint_url)
      @mutex.synchronize do
        now = Time.now
        bucket = @buckets[endpoint_url]
        if bucket.nil? || (now - bucket[:window_start]) >= RATE_WINDOW_SECONDS
          @buckets[endpoint_url] = { count: 1, window_start: now }
          return true
        end
        return false if bucket[:count] >= RATE_LIMIT

        bucket[:count] += 1
        true
      end
    end

    def now_iso
      Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")
    end
  end

  # A parsed, already-verified inbound command from the platform
  # (session_revocation or ip_block) — the inbound direction of the closed
  # loop. Call WebhookVerifier.verify first; this does not re-verify the
  # signature.
  module WebhookCommand
    def self.parse(raw_body)
      JSON.parse(raw_body)
    end
  end
end
