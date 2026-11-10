# frozen_string_literal: true

require_relative "bounded_map"

module DevFortress
  # Internal Closed-Loop Protection Engine.
  #
  # Port of the Node SDK's `internal-closed-loop-engine.ts`
  # (`InternalClosedLoopEngine`), following the same structure as this
  # session's Python port
  # (devfortress-python/src/devfortress/internal_closed_loop_engine.py).
  #
  # Three tiers:
  #
  #   Tier 1: Deterministic rule engine (<1ms) — regex, scanner signature,
  #           sensitive-file, credential-stuffing, and agent-tool rules.
  #   Tier 2: Optional custom scorer — anything responding to `#call`
  #           (a Proc/lambda or any object). Unimplemented by default: no
  #           scorer is wired in unless the caller passes one; #evaluate
  #           simply skips Tier 2 in that case (same as Node's behaviour
  #           when `tier2Scorer` is unset, and Python's when
  #           `tier2_scorer` is `None`). This engine does not build a Ruby
  #           equivalent of Node's MLClassifier adapter — that is
  #           Node-specific and out of scope here.
  #   Tier 3: Relay — fires the `on_relay` callable for non-'allow'
  #           decisions when `enable_external_relay` is true (hybrid mode
  #           only). This engine has no HTTP client or platform
  #           credentials of its own by design; the caller's relay
  #           callback does the actual platform call (see client.rb's
  #           `_relay_internal_decision_to_platform`).
  #
  # State (blocked IPs/users/sessions, quarantined agents, rate-limiter
  # entries, audit log) is bounded in-memory, lives for the engine
  # instance's lifetime, and is never persisted — reusing this SDK's own
  # BoundedMap, exactly like Node's and Python's engines.
  #
  # Ruby's Onigmo regex engine was independently verified against Node's
  # V8/ECMA regex for every Tier 1 pattern below (see this session's
  # report). One real divergence was found and fixed: Ruby's `$` anchor
  # matches at the end of *any line* (there is no non-multiline mode for
  # `^`/`$` in Ruby), whereas JS's bare `$` (no `/m` flag) matches only at
  # the end of the *string*. The `path_traversal` rule's
  # "ends with ..\\" pattern relied on `$` meaning absolute string end, so
  # it is anchored with `\z` here instead of `$` to preserve Node's exact
  # semantics (a multi-line request path containing "..\\" mid-string,
  # followed by a line break and more content, would otherwise match in
  # Ruby but not in Node). No other pattern in this engine is affected:
  # every other `$`/`^` use already has a `\s`-based alternative that
  # already covers embedded newlines on both engines, so the two engines'
  # line-vs-string anchor difference produces no observable behavioural
  # difference there.
  class InternalClosedLoopEngine
    # ── Default Attack Pattern Rules (Tier 1) ──────────────────────────
    # Copied as literally as possible from internal-closed-loop-engine.ts;
    # Ruby's /pattern/ literal syntax accepts the TS source's own escaping
    # of internal slashes unchanged. See the class comment above for the
    # one anchor fix (`$` -> `\z`) found necessary by direct verification.

    SQL_INJECTION_STRICT = [
      /(?:^|\s)(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)(?:\s|\z)/i,
      /(?:'|")\s*OR\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|"[^"]*"\s*=\s*"[^"]*")/i,
      /(?:'|")\s*;\s*(?:--|\/\*)/,
      /(\bxp_\w+)/i,
    ].freeze

    SQL_INJECTION_MODERATE = [/(\/\*.*\*\/)/, /(\bEXEC\b|\bEXECUTE\b)\s*\(/i].freeze

    XSS_PATTERNS = [
      /<script[\s>]/i,
      /javascript\s*:/i,
      /on(load|error|click|mouseover|submit|focus|blur)\s*=/i,
      /(<iframe|<object|<embed|<applet)/i,
      /(document\.(cookie|write|location))/i,
      /(window\.(location|open))/i,
    ].freeze

    PATH_TRAVERSAL_PATTERNS = [
      /\.\.\//,
      /\.\.%2[fF]/,
      /\.\.\\\z/, # was `$` in Node; `\z` here is the Ruby-exact equivalent (see class comment)
      /%2e%2e[%\/\\]/i,
      /\/etc\/(passwd|shadow|hosts)/,
      /\/proc\/self/,
      /(\/\.env|\/\.git|\/\.ssh)/,
    ].freeze

    SCANNER_SIGNATURES = %w[sqlmap nikto nmap dirbuster gobuster].map { |p| Regexp.new(p, Regexp::IGNORECASE) } +
                          [Regexp.new('wpscan', Regexp::IGNORECASE),
                           Regexp.new('burp\s*suite', Regexp::IGNORECASE),
                           Regexp.new('acunetix', Regexp::IGNORECASE),
                           Regexp.new('nessus', Regexp::IGNORECASE),
                           Regexp.new('masscan', Regexp::IGNORECASE),
                           Regexp.new('zgrab', Regexp::IGNORECASE),
                           Regexp.new('nuclei', Regexp::IGNORECASE)].freeze

    SENSITIVE_FILE_PATTERNS = [
      /\/\.env/,
      /\/\.git/,
      /\/\.ssh/,
      /\/wp-admin/,
      /\/wp-login/,
      /\/phpmyadmin/i,
      /\/admin\.php/,
      /\/\.htaccess/,
      /\/\.htpasswd/,
      /\/server-status/,
      /\/actuator/,
      /\/debug\//,
    ].freeze

    AUTH_PATHS = ["/login", "/signin", "/auth", "/api/auth", "/api/login", "/oauth/token"].freeze
    DANGEROUS_TOOLS = %w[shell_exec eval exec rm sudo chmod kill].freeze

    # ── Request / Result value objects ─────────────────────────────────

    Request = Struct.new(
      :ip, :method, :path, :user_agent, :user_id, :session_id, :body, :query,
      :headers, :agent_id, :tool_name, :timestamp,
      keyword_init: true
    ) do
      def initialize(**kwargs)
        super
        self.headers ||= {}
      end
    end

    Action = Struct.new(:type, :target, :reason, :ttl_seconds, :timestamp, :event_id, keyword_init: true)
    Result = Struct.new(:decision, :score, :tier, :matched_rules, :evaluation_time_us, :actions, :event_id, keyword_init: true)
    AuditEntry = Struct.new(
      :event_id, :timestamp, :ip, :decision, :score, :tier, :matched_rules, :user_id, :agent_id, :path, :method,
      keyword_init: true
    )
    Rule = Struct.new(:name, :description, :severity, :score, :decision, :match, :enabled, keyword_init: true)

    BlockEntry = Struct.new(:expires_at, :reason, keyword_init: true)
    QuarantineEntry = Struct.new(:reason, :timestamp, keyword_init: true)
    RateLimitEntry = Struct.new(:timestamps, :blocked, keyword_init: true) do
      def initialize(**kwargs)
        super
        self.timestamps ||= []
      end
    end

    attr_reader :fail_mode, :enable_external_relay

    def initialize(
      fail_mode: :closed,
      enable_external_relay: false,
      max_blocked_entries: 10_000,
      max_rate_limit_entries: 50_000,
      max_audit_entries: 100_000,
      default_block_ttl_seconds: 3600,
      tier2_scorer: nil,
      block_threshold: 85,
      rate_limit_threshold: 60,
      rate_limit_max: 100,
      rate_limit_window_seconds: 60.0,
      debug: false,
      on_action: nil,
      on_relay: nil,
      logger: nil
    )
      @fail_mode = fail_mode.to_sym
      @enable_external_relay = enable_external_relay
      @max_audit_entries = max_audit_entries
      @default_block_ttl_seconds = default_block_ttl_seconds
      @tier2_scorer = tier2_scorer
      @block_threshold = block_threshold
      @rate_limit_threshold = rate_limit_threshold
      @rate_limit_max = rate_limit_max
      @rate_limit_window_seconds = rate_limit_window_seconds
      @debug = debug
      @on_action = on_action
      @on_relay = on_relay
      @logger = logger

      @blocked_ips = BoundedMap.new(max_blocked_entries)
      @blocked_users = BoundedMap.new(max_blocked_entries)
      @blocked_sessions = BoundedMap.new(max_blocked_entries)
      @quarantined_agents = BoundedMap.new(max_blocked_entries)
      @rate_limiter = BoundedMap.new(max_rate_limit_entries)
      @audit_log = []
      @audit_mutex = Mutex.new
      @rules = []
      @event_counter = 0
      @event_counter_mutex = Mutex.new

      register_default_rules
      log(:info, "Internal Closed-Loop Engine initialized (fail_mode=#{@fail_mode})")
    end

    # ── Public API ──────────────────────────────────────────────────

    # Evaluates +req+ (an InternalCLEngine::Request) through the 3-tier
    # engine. Call this for every inbound request, before it reaches the
    # application. Never raises: an uncaught error inside a rule or
    # Tier 2/3 is contained and falls back to +fail_mode+.
    def evaluate(req)
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      now = req.timestamp || Time.now.to_f
      event_id = generate_event_id

      begin
        pre_check = check_blocked(req, now)
        if pre_check
          decision, reason = pre_check
          result = Result.new(
            decision: decision, score: 100, tier: 1, matched_rules: [reason],
            evaluation_time_us: elapsed_us(start), actions: [], event_id: event_id
          )
          record_audit(result, req)
          return result
        end

        tier1_decision, tier1_score, tier1_rules = evaluate_tier1(req)
        if tier1_decision != :allow
          actions = execute_actions(tier1_decision, tier1_rules, req, event_id, now)
          result = Result.new(
            decision: tier1_decision, score: tier1_score, tier: 1, matched_rules: tier1_rules,
            evaluation_time_us: elapsed_us(start), actions: actions, event_id: event_id
          )
          record_audit(result, req)
          relay_to_external(result, req) if @enable_external_relay
          return result
        end

        if check_rate_limit(req.ip, now)
          actions = execute_actions(:rate_limit, ["rate_limit_exceeded"], req, event_id, now)
          result = Result.new(
            decision: :rate_limit, score: 65, tier: 1, matched_rules: ["rate_limit_exceeded"],
            evaluation_time_us: elapsed_us(start), actions: actions, event_id: event_id
          )
          record_audit(result, req)
          return result
        end

        record_request(req.ip, now)

        # ── Tier 2: optional custom scorer — unimplemented/pass-through
        # by default. Skipped entirely when no scorer is configured. ──
        if @tier2_scorer
          score = @tier2_scorer.call(req).to_f

          if score >= @block_threshold
            actions = execute_actions(:block, ["tier2_ml_score"], req, event_id, now)
            result = Result.new(
              decision: :block, score: score, tier: 2, matched_rules: ["tier2_ml_score"],
              evaluation_time_us: elapsed_us(start), actions: actions, event_id: event_id
            )
            record_audit(result, req)
            relay_to_external(result, req) if @enable_external_relay
            return result
          elsif score >= @rate_limit_threshold
            result = Result.new(
              decision: :rate_limit, score: score, tier: 2, matched_rules: ["tier2_ml_elevated"],
              evaluation_time_us: elapsed_us(start), actions: [], event_id: event_id
            )
            record_audit(result, req)
            return result
          end
        end

        Result.new(decision: :allow, score: 0, tier: 1, matched_rules: [], evaluation_time_us: elapsed_us(start),
                    actions: [], event_id: event_id)
      rescue StandardError => e
        log(:error, "Evaluation error: #{e.message}")
        if @fail_mode == :closed
          Result.new(decision: :block, score: 100, tier: 1, matched_rules: ["fail_closed_error"],
                      evaluation_time_us: elapsed_us(start), actions: [], event_id: event_id)
        else
          Result.new(decision: :allow, score: 0, tier: 1, matched_rules: ["fail_open_error"],
                      evaluation_time_us: elapsed_us(start), actions: [], event_id: event_id)
        end
      end
    end

    def block_ip(ip, reason, ttl_seconds: nil)
      ttl = ttl_seconds || @default_block_ttl_seconds
      @blocked_ips.set(ip, BlockEntry.new(expires_at: Time.now.to_f + ttl, reason: reason))
      log(:info, "IP blocked: #{ip} — #{reason} (TTL: #{ttl}s)")
    end

    def unblock_ip(ip)
      existed = @blocked_ips.has?(ip)
      @blocked_ips.delete(ip)
      log(:info, "IP unblocked: #{ip}") if existed
      existed
    end

    def block_user(user_id, reason, ttl_seconds: nil)
      ttl = ttl_seconds || @default_block_ttl_seconds
      @blocked_users.set(user_id, BlockEntry.new(expires_at: Time.now.to_f + ttl, reason: reason))
      log(:info, "User blocked: #{user_id} — #{reason}")
    end

    def block_session(session_id, reason, ttl_seconds: nil)
      ttl = ttl_seconds || @default_block_ttl_seconds
      @blocked_sessions.set(session_id, BlockEntry.new(expires_at: Time.now.to_f + ttl, reason: reason))
      log(:info, "Session blocked: #{session_id} — #{reason}")
    end

    def quarantine_agent(agent_id, reason)
      @quarantined_agents.set(agent_id, QuarantineEntry.new(reason: reason, timestamp: Time.now.to_f))
      log(:info, "Agent quarantined: #{agent_id} — #{reason}")
    end

    def unquarantine_agent(agent_id)
      existed = @quarantined_agents.has?(agent_id)
      @quarantined_agents.delete(agent_id)
      log(:info, "Agent unquarantined: #{agent_id}") if existed
      existed
    end

    # Ruby-idiomatic equivalent of Node's isIPBlocked / Python's
    # is_ip_blocked (dropping the redundant "is_" prefix, matching this
    # SDK's own convention elsewhere, e.g. PlatformCircuitBreaker#rules_stale?).
    def ip_blocked?(ip)
      entry = @blocked_ips.get(ip)
      return false unless entry
      if Time.now.to_f > entry.expires_at
        @blocked_ips.delete(ip)
        return false
      end
      true
    end

    def agent_quarantined?(agent_id)
      @quarantined_agents.has?(agent_id)
    end

    def add_rule(rule)
      @rules << rule
      log(:debug, "Rule added: #{rule.name}")
    end

    def remove_rule(name)
      idx = @rules.find_index { |r| r.name == name }
      return false unless idx

      @rules.delete_at(idx)
      log(:debug, "Rule removed: #{name}")
      true
    end

    def rules
      @rules.map do |r|
        { name: r.name, description: r.description, severity: r.severity, score: r.score, decision: r.decision,
          enabled: r.enabled }
      end
    end

    def audit_log(limit: 100)
      @audit_mutex.synchronize { @audit_log.last(limit) }
    end

    def stats
      {
        blocked_ips: @blocked_ips.size,
        blocked_users: @blocked_users.size,
        blocked_sessions: @blocked_sessions.size,
        quarantined_agents: @quarantined_agents.size,
        rate_limit_entries: @rate_limiter.size,
        audit_log_size: @audit_mutex.synchronize { @audit_log.length },
        rules_count: @rules.length,
        fail_mode: @fail_mode,
      }
    end

    def import_blocked_ips(entries)
      count = 0
      entries.each do |entry|
        block_ip(entry[:ip], entry[:reason], ttl_seconds: entry[:ttl_seconds])
        count += 1
      end
      count
    end

    # Resets all state. For testing.
    def reset!
      @blocked_ips.clear
      @blocked_users.clear
      @blocked_sessions.clear
      @quarantined_agents.clear
      @rate_limiter.clear
      @audit_mutex.synchronize { @audit_log = [] }
      @event_counter_mutex.synchronize { @event_counter = 0 }
    end

    private

    def elapsed_us(start)
      (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1_000_000
    end

    def check_blocked(req, now)
      ip_block = @blocked_ips.get(req.ip)
      if ip_block
        if now > ip_block.expires_at
          @blocked_ips.delete(req.ip)
        else
          return [:block, "ip_blocked:#{ip_block.reason}"]
        end
      end

      if req.user_id
        user_block = @blocked_users.get(req.user_id)
        if user_block
          if now > user_block.expires_at
            @blocked_users.delete(req.user_id)
          else
            return [:block, "user_blocked:#{user_block.reason}"]
          end
        end
      end

      if req.session_id
        session_block = @blocked_sessions.get(req.session_id)
        if session_block
          if now > session_block.expires_at
            @blocked_sessions.delete(req.session_id)
          else
            return [:block, "session_blocked:#{session_block.reason}"]
          end
        end
      end

      if req.agent_id && @quarantined_agents.has?(req.agent_id)
        return [:quarantine, "agent_quarantined:#{req.agent_id}"]
      end

      nil
    end

    def evaluate_tier1(req)
      matched_rules = []
      max_score = 0.0
      decision = :allow

      @rules.each do |rule|
        next unless rule.enabled

        begin
          if rule.match.call(req)
            matched_rules << rule.name
            if rule.score > max_score
              max_score = rule.score
              decision = rule.decision
            end
          end
        rescue StandardError
          # An individual rule's error must not crash the whole engine.
          log(:error, "Rule #{rule.name} raised an error")
        end
      end

      [decision, max_score, matched_rules]
    end

    def check_rate_limit(ip, now)
      entry = @rate_limiter.get(ip)
      return false unless entry

      window_start = now - @rate_limit_window_seconds
      entry.timestamps = entry.timestamps.select { |t| t > window_start }
      if entry.timestamps.length >= @rate_limit_max
        entry.blocked = true
        return true
      end
      false
    end

    def record_request(ip, now)
      entry = @rate_limiter.get(ip) || RateLimitEntry.new
      entry.timestamps << now
      @rate_limiter.set(ip, entry)
    end

    def execute_actions(decision, matched_rules, req, event_id, now)
      actions = []
      ttl = @default_block_ttl_seconds
      reason = matched_rules.join(", ")

      if decision == :block || decision == :quarantine
        @blocked_ips.set(req.ip, BlockEntry.new(expires_at: now + ttl, reason: reason))
        actions << Action.new(type: :block_ip, target: req.ip, reason: reason, ttl_seconds: ttl, timestamp: now,
                               event_id: event_id)

        if req.session_id
          @blocked_sessions.set(req.session_id, BlockEntry.new(expires_at: now + ttl, reason: reason))
          actions << Action.new(type: :block_session, target: req.session_id, reason: reason, ttl_seconds: ttl,
                                 timestamp: now, event_id: event_id)
        end

        if req.agent_id
          @quarantined_agents.set(req.agent_id, QuarantineEntry.new(reason: reason, timestamp: now))
          actions << Action.new(type: :quarantine_agent, target: req.agent_id, reason: reason, ttl_seconds: 0,
                                 timestamp: now, event_id: event_id)
        end
      end

      if @on_action
        actions.each do |action|
          begin
            @on_action.call(action)
          rescue StandardError
            log(:error, "on_action callback error for #{action.type}")
          end
        end
      end

      actions
    end

    def record_audit(result, req)
      @audit_mutex.synchronize do
        if @audit_log.length >= @max_audit_entries
          @audit_log.shift([1, (@max_audit_entries * 0.1).to_i].max)
        end

        @audit_log << AuditEntry.new(
          event_id: result.event_id,
          timestamp: req.timestamp || Time.now.to_f,
          ip: req.ip,
          decision: result.decision,
          score: result.score,
          tier: result.tier,
          matched_rules: result.matched_rules,
          user_id: req.user_id,
          agent_id: req.agent_id,
          path: req.path,
          method: req.method,
        )
      end
    end

    def relay_to_external(result, req)
      # Tier 3: relay via the caller-supplied on_relay callable. This
      # engine has no HTTP client or platform credentials of its own by
      # design — the caller does the actual platform call.
      log(:debug, "Tier 3 relay: #{result.event_id} -> external platform")
      return unless @on_relay

      begin
        @on_relay.call(result, req)
      rescue StandardError => e
        log(:error, "on_relay callback error for #{result.event_id}: #{e.message}")
      end
    end

    def generate_event_id
      counter = @event_counter_mutex.synchronize { @event_counter += 1 }
      ts = (Time.now.to_f * 1000).to_i.to_s(16)
      counter_hex = counter.to_s(16).rjust(4, "0")
      rand_hex = rand(0x10000).to_s(16).rjust(4, "0")
      "icl_#{ts}_#{counter_hex}_#{rand_hex}"
    end

    # Mirrors Node's `.filter(Boolean)` / Python's `if t` filtering: drops
    # both nil and empty-string values, so an absent/empty query string or
    # body never gets regex-matched against (it never would match, but
    # this keeps behaviour identical rather than merely equivalent).
    def present(*values)
      values.reject { |v| v.nil? || v.empty? }
    end

    def register_default_rules
      @rules << Rule.new(
        name: "sql_injection",
        description: "Detects SQL injection patterns context-aware (strict on path/query, moderate on body)",
        severity: "critical", score: 95, decision: :block, enabled: true,
        match: lambda do |req|
          strict_targets = present(req.path, req.query)
          next true if strict_targets.any? { |t| SQL_INJECTION_STRICT.any? { |p| p.match?(t) } }
          next true if strict_targets.any? { |t| SQL_INJECTION_MODERATE.any? { |p| p.match?(t) } }

          body_targets = present(req.body, *req.headers.values)
          body_targets.any? { |t| SQL_INJECTION_STRICT.any? { |p| p.match?(t) } }
        end
      )

      @rules << Rule.new(
        name: "xss_attempt",
        description: "Detects cross-site scripting patterns",
        severity: "high", score: 90, decision: :block, enabled: true,
        match: lambda do |req|
          targets = present(req.path, req.query, req.body)
          targets.any? { |t| XSS_PATTERNS.any? { |p| p.match?(t) } }
        end
      )

      @rules << Rule.new(
        name: "path_traversal",
        description: "Detects directory traversal attempts",
        severity: "high", score: 90, decision: :block, enabled: true,
        match: lambda do |req|
          targets = present(req.path, req.query)
          targets.any? { |t| PATH_TRAVERSAL_PATTERNS.any? { |p| p.match?(t) } }
        end
      )

      @rules << Rule.new(
        name: "scanner_detected",
        description: "Detects known vulnerability scanner user agents",
        severity: "medium", score: 75, decision: :block, enabled: true,
        match: lambda do |req|
          next false unless req.user_agent

          SCANNER_SIGNATURES.any? { |p| p.match?(req.user_agent) }
        end
      )

      @rules << Rule.new(
        name: "sensitive_file_access",
        description: "Detects access to sensitive files (.env, .git, wp-admin, etc.)",
        severity: "high", score: 85, decision: :block, enabled: true,
        match: ->(req) { SENSITIVE_FILE_PATTERNS.any? { |p| p.match?(req.path) } }
      )

      @rules << Rule.new(
        name: "credential_stuffing_pattern",
        description: "Detects credential stuffing via POST to auth endpoints",
        severity: "high", score: 80, decision: :rate_limit, enabled: true,
        match: lambda do |req|
          next false unless req.method == "POST"

          path_lower = req.path.downcase
          AUTH_PATHS.any? { |p| path_lower.include?(p) }
        end
      )

      @rules << Rule.new(
        name: "agent_unsanctioned_tool",
        description: "Detects agent attempting to use dangerous tools",
        severity: "critical", score: 95, decision: :quarantine, enabled: true,
        match: lambda do |req|
          next false unless req.agent_id && req.tool_name

          DANGEROUS_TOOLS.include?(req.tool_name.downcase)
        end
      )
    end

    def log(level, message)
      return if !@debug && level == :debug

      prefix = "[DevFortress ICL]"
      if @logger
        begin
          @logger.log(level.to_s, "#{prefix} #{message}")
        rescue StandardError
          # A failing logger must not reach the host application either.
        end
      elsif level == :error || level == :warn || @debug
        warn("#{prefix} #{message}")
      end
    end
  end
end
