package net.devfortress;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * DevFortress SDK — Graduated Rate Limiter (Invention A3). Mirrors
 * {@code packages/devfortress-sdk/src/graduated-rate-limiter.ts}.
 *
 * <p>Implements alias-scoped graduated rate limiting with multi-stage
 * response escalation. Addresses GAP-A3-1 through GAP-A3-4:
 * <ul>
 *   <li>GAP-A3-1: Latency jitter (+/-20%) in soft-limit injection</li>
 *   <li>GAP-A3-2: Per-endpoint hierarchical rate limits (configurable)</li>
 *   <li>GAP-A3-3: Burst detection (1-second micro-window)</li>
 *   <li>GAP-A3-4: Escalating cooldowns (60s-&gt;120s-&gt;240s, revoke after 3)</li>
 * </ul>
 *
 * <p>Four-stage graduated response:
 * <ul>
 *   <li>Stage 1: Observation (&lt; 50% of limit)</li>
 *   <li>Stage 2: Warning (50%-75% of limit)</li>
 *   <li>Stage 3: Soft-limit with latency injection (75%-100% of limit)</li>
 *   <li>Stage 4: Hard-block with escalating cooldowns (&gt;= 100% of limit)</li>
 *   <li>Stage 5: Alias revocation (&gt;= 120% of limit or 3 consecutive blocks)</li>
 * </ul>
 *
 * <p>Safe for concurrent use.
 */
public final class GraduatedRateLimiter {

    /** Which graduated response stage a {@link #check} call triggered. */
    public enum RateLimitStage {
        OBSERVATION, WARNING, SOFT_LIMIT, HARD_BLOCK, REVOCATION
    }

    /** The outcome of one {@link #check} call. */
    public record RateLimitResult(
            RateLimitStage stage,
            int currentRate,
            int limit,
            double ratio,
            long injectedLatencyMs,
            boolean blocked,
            boolean revoke,
            long cooldownSeconds,
            int remaining,
            boolean burstDetected) {
    }

    private static final class Entry {
        List<Long> timestamps = new ArrayList<>();
        long cooldownUntil = 0L;
        int consecutiveBlocks = 0;
        boolean revoked = false;
        List<Long> burstTimestamps = new ArrayList<>();
    }

    private final Object lock = new Object();
    private final Map<String, Entry> entries = new HashMap<>();
    /** Insertion order, for oldest-first eviction mirroring Node's Map iteration order. */
    private final List<String> order = new ArrayList<>();

    private final int defaultLimit;
    private final long windowMs;
    private final long softLimitBaseLatencyMs;
    private final int maxEntries;
    private final Map<String, Integer> endpointLimits;
    private final int burstLimit;
    private final long initialCooldownSeconds;
    private final int maxConsecutiveBlocks;

    private final ScheduledExecutorService cleanupExecutor;
    private final ScheduledFuture<?> cleanupTask;

    public GraduatedRateLimiter(Config config) {
        this.defaultLimit = config.defaultLimit();
        this.windowMs = config.windowMs();
        this.softLimitBaseLatencyMs = config.softLimitBaseLatencyMs();
        this.maxEntries = config.maxEntries();
        this.endpointLimits = new HashMap<>(config.endpointLimits());
        this.burstLimit = config.burstLimit();
        this.initialCooldownSeconds = config.initialCooldownSeconds();
        this.maxConsecutiveBlocks = config.maxConsecutiveBlocks();

        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "devfortress-rate-limiter-cleanup");
            t.setDaemon(true); // mirrors Node's timer.unref(): never blocks process exit
            return t;
        });
        this.cleanupTask = cleanupExecutor.scheduleAtFixedRate(this::cleanup, 30, 30, TimeUnit.SECONDS);
    }

    public GraduatedRateLimiter() {
        this(Config.defaults());
    }

    /** Configuration for a {@link GraduatedRateLimiter}. */
    public record Config(
            int defaultLimit,
            long windowMs,
            long softLimitBaseLatencyMs,
            int maxEntries,
            Map<String, Integer> endpointLimits,
            int burstLimit,
            long initialCooldownSeconds,
            int maxConsecutiveBlocks) {

        public static Config defaults() {
            return new Config(100, 60_000L, 2000L, 50_000, Map.of(), 20, 60L, 3);
        }

        public Config withDefaultLimit(int value) {
            return new Config(value, windowMs, softLimitBaseLatencyMs, maxEntries, endpointLimits,
                    burstLimit, initialCooldownSeconds, maxConsecutiveBlocks);
        }

        public Config withSoftLimitBaseLatencyMs(long value) {
            return new Config(defaultLimit, windowMs, value, maxEntries, endpointLimits,
                    burstLimit, initialCooldownSeconds, maxConsecutiveBlocks);
        }

        public Config withMaxEntries(int value) {
            return new Config(defaultLimit, windowMs, softLimitBaseLatencyMs, value, endpointLimits,
                    burstLimit, initialCooldownSeconds, maxConsecutiveBlocks);
        }

        public Config withEndpointLimits(Map<String, Integer> value) {
            return new Config(defaultLimit, windowMs, softLimitBaseLatencyMs, maxEntries, value,
                    burstLimit, initialCooldownSeconds, maxConsecutiveBlocks);
        }

        public Config withBurstLimit(int value) {
            return new Config(defaultLimit, windowMs, softLimitBaseLatencyMs, maxEntries, endpointLimits,
                    value, initialCooldownSeconds, maxConsecutiveBlocks);
        }

        public Config withInitialCooldownSeconds(long value) {
            return new Config(defaultLimit, windowMs, softLimitBaseLatencyMs, maxEntries, endpointLimits,
                    burstLimit, value, maxConsecutiveBlocks);
        }

        public Config withMaxConsecutiveBlocks(int value) {
            return new Config(defaultLimit, windowMs, softLimitBaseLatencyMs, maxEntries, endpointLimits,
                    burstLimit, initialCooldownSeconds, value);
        }
    }

    /**
     * Checks the rate limit for an alias (identified by {@code key}, typically
     * an IP or session ID). Records the request and returns the graduated
     * response. {@code endpoint} is optional (may be {@code null}) and enables
     * per-endpoint limits (GAP-A3-2).
     */
    public RateLimitResult check(String key, String endpoint) {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            Entry entry = entries.get(key);
            boolean existed = entry != null;
            if (entry == null) {
                entry = new Entry();
            }

            if (entry.revoked) {
                return new RateLimitResult(RateLimitStage.REVOCATION, 0, 0, Double.POSITIVE_INFINITY,
                        0, true, false, 0, 0, false);
            }

            if (entry.cooldownUntil > now) {
                long cooldownRemaining = (long) Math.ceil((entry.cooldownUntil - now) / 1000.0);
                return new RateLimitResult(RateLimitStage.HARD_BLOCK, entry.timestamps.size(),
                        effectiveLimit(endpoint), 1.0, 0, true, false, cooldownRemaining, 0, false);
            }

            long windowStart = now - windowMs;
            entry.timestamps.removeIf(t -> t <= windowStart);

            // GAP-A3-3: clean burst micro-window (1 second).
            long burstWindowStart = now - 1000L;
            entry.burstTimestamps.removeIf(t -> t <= burstWindowStart);

            entry.timestamps.add(now);
            entry.burstTimestamps.add(now);

            if (!existed && entries.size() >= maxEntries) {
                evictOldest();
            }
            if (!existed) {
                order.add(key);
            }
            entries.put(key, entry);

            int limit = effectiveLimit(endpoint);
            int currentRate = entry.timestamps.size();
            double ratio = (double) currentRate / limit;

            // GAP-A3-3: burst detection.
            boolean burstDetected = entry.burstTimestamps.size() > burstLimit;

            if (ratio >= 1.2 || entry.consecutiveBlocks >= maxConsecutiveBlocks) {
                entry.revoked = true;
                return new RateLimitResult(RateLimitStage.REVOCATION, currentRate, limit, ratio, 0,
                        true, true, 0, 0, burstDetected);
            }

            if (ratio >= 1.0 || burstDetected) {
                entry.consecutiveBlocks++;
                long cooldownMultiplier = 1L << (entry.consecutiveBlocks - 1);
                long cooldownSeconds = initialCooldownSeconds * cooldownMultiplier;
                entry.cooldownUntil = now + cooldownSeconds * 1000L;

                return new RateLimitResult(RateLimitStage.HARD_BLOCK, currentRate, limit, ratio, 0,
                        true, false, cooldownSeconds, 0, burstDetected);
            }

            if (ratio >= 0.75) {
                entry.consecutiveBlocks = 0;

                double progress = (ratio - 0.75) / 0.25;
                double baseLatency = softLimitBaseLatencyMs * Math.pow(progress, 2);
                // GAP-A3-1: add +/-20% random jitter.
                double jitter = 0.8 + 0.4 * ThreadLocalRandom.current().nextDouble();
                long injectedLatencyMs = Math.round(baseLatency * jitter);

                return new RateLimitResult(RateLimitStage.SOFT_LIMIT, currentRate, limit, ratio,
                        injectedLatencyMs, false, false, 0, Math.max(0, limit - currentRate), burstDetected);
            }

            if (ratio >= 0.5) {
                entry.consecutiveBlocks = 0;
                return new RateLimitResult(RateLimitStage.WARNING, currentRate, limit, ratio, 0,
                        false, false, 0, Math.max(0, limit - currentRate), false);
            }

            entry.consecutiveBlocks = 0;
            return new RateLimitResult(RateLimitStage.OBSERVATION, currentRate, limit, ratio, 0,
                    false, false, 0, Math.max(0, limit - currentRate), false);
        }
    }

    public RateLimitResult check(String key) {
        return check(key, null);
    }

    /** Manually revokes an alias (e.g. from an external security decision). */
    public void revokeAlias(String key) {
        synchronized (lock) {
            Entry entry = entries.get(key);
            if (entry == null) {
                entry = new Entry();
                entry.revoked = true;
                order.add(key);
            } else {
                entry.revoked = true;
            }
            entries.put(key, entry);
        }
    }

    /** Resets an alias's rate limit state (e.g. after an admin override). */
    public void resetAlias(String key) {
        synchronized (lock) {
            entries.remove(key);
        }
    }

    /** Returns whether an alias has been revoked. */
    public boolean isRevoked(String key) {
        synchronized (lock) {
            Entry entry = entries.get(key);
            return entry != null && entry.revoked;
        }
    }

    /** Sets per-endpoint rate limits (merged into any existing endpoint limits). GAP-A3-2. */
    public void setEndpointLimits(Map<String, Integer> limits) {
        synchronized (lock) {
            endpointLimits.putAll(limits);
        }
    }

    /** Returns the current number of tracked aliases. */
    public int size() {
        synchronized (lock) {
            return entries.size();
        }
    }

    private int effectiveLimit(String endpoint) {
        if (endpoint == null || endpointLimits.isEmpty()) {
            return defaultLimit;
        }
        Integer exact = endpointLimits.get(endpoint);
        if (exact != null) {
            return exact;
        }
        for (Map.Entry<String, Integer> e : endpointLimits.entrySet()) {
            String pattern = e.getKey();
            if (pattern.endsWith("*") && endpoint.startsWith(pattern.substring(0, pattern.length() - 1))) {
                return e.getValue();
            }
        }
        return defaultLimit;
    }

    private void evictOldest() {
        while (!order.isEmpty()) {
            String oldest = order.remove(0);
            if (entries.remove(oldest) != null) {
                return;
            }
        }
    }

    /** Removes entries with no recent activity that are not in cooldown and not revoked. */
    private void cleanup() {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            long windowStart = now - windowMs;

            entries.entrySet().removeIf(e -> {
                Entry entry = e.getValue();
                boolean hasRecentActivity = entry.timestamps.stream().anyMatch(t -> t > windowStart);
                boolean inCooldown = entry.cooldownUntil > now;
                return !hasRecentActivity && !inCooldown && !entry.revoked;
            });
        }
    }

    /** Stops the limiter's cleanup task and clears its state. */
    public void destroy() {
        cleanupTask.cancel(false);
        cleanupExecutor.shutdown();
        synchronized (lock) {
            entries.clear();
            order.clear();
        }
    }
}
