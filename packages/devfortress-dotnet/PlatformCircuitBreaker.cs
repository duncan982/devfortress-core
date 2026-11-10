namespace DevFortress;

/// <summary>A <see cref="PlatformCircuitBreaker"/>'s state.</summary>
public enum CircuitState { Closed, Open, HalfOpen }

/// <summary>Diagnostics info from <see cref="PlatformCircuitBreaker.GetDiagnostics"/>.</summary>
public sealed record CircuitBreakerDiagnostics(
    CircuitState State,
    int FailureCount,
    DateTime LastFailureTime,
    TimeSpan TimeUntilRecoveryAttempt,
    bool RulesStale,
    TimeSpan StaleDuration);

/// <summary>
/// DevFortress SDK — Platform Circuit Breaker. Mirrors
/// <c>packages/devfortress-sdk/src/circuit-breaker.ts</c>.
///
/// <para>Monitors connectivity to the DevFortress platform and provides
/// automatic failover from external to internal closed-loop mode.</para>
///
/// <para>Three states: Closed (platform reachable, external CL active),
/// Open (platform unreachable, internal CL takes over), HalfOpen
/// (testing if the platform has recovered).</para>
///
/// <para>Transition rules: Closed-&gt;Open after FailureThreshold
/// consecutive failures; Open-&gt;HalfOpen after RecoveryTime elapsed;
/// HalfOpen-&gt;Closed on first success; HalfOpen-&gt;Open on first
/// failure.</para>
///
/// <para>Thread-safe.</para>
/// </summary>
public sealed class PlatformCircuitBreaker
{
    /// <summary>Rules older than 5 minutes without a platform sync are considered stale.</summary>
    public static readonly TimeSpan StaleThreshold = TimeSpan.FromMinutes(5);

    private readonly object _lock = new();
    private CircuitState _state = CircuitState.Closed;
    private int _failureCount;
    private DateTime _lastFailureTime = DateTime.MinValue;
    private readonly int _failureThreshold;
    private readonly TimeSpan _recoveryTime;
    private readonly Action<CircuitState, CircuitState, string>? _onStateChange;

    // When internal rules became stale (circuit opened); null if not stale.
    private DateTime? _staleSince;

    public PlatformCircuitBreaker(
        int failureThreshold = 3,
        TimeSpan? recoveryTime = null,
        Action<CircuitState, CircuitState, string>? onStateChange = null)
    {
        _failureThreshold = failureThreshold;
        _recoveryTime = recoveryTime ?? TimeSpan.FromMinutes(1);
        _onStateChange = onStateChange;
    }

    /// <summary>
    /// Returns whether external platform calls should be attempted
    /// (true if closed or half-open).
    /// </summary>
    public bool ShouldCallExternal()
    {
        lock (_lock)
        {
            if (_state == CircuitState.Closed)
            {
                return true;
            }

            if (_state == CircuitState.Open)
            {
                if (DateTime.UtcNow - _lastFailureTime >= _recoveryTime)
                {
                    Transition(CircuitState.HalfOpen, "recovery_timeout_elapsed");
                    return true; // allow one test call
                }
                return false;
            }

            // HalfOpen: allow the test call.
            return true;
        }
    }

    /// <summary>Records a successful external call.</summary>
    public void RecordSuccess()
    {
        lock (_lock)
        {
            if (_state == CircuitState.HalfOpen)
            {
                Transition(CircuitState.Closed, "test_call_succeeded");
            }
            _failureCount = 0;
            _staleSince = null;
        }
    }

    /// <summary>Records a failed external call.</summary>
    public void RecordFailure()
    {
        lock (_lock)
        {
            _failureCount++;
            _lastFailureTime = DateTime.UtcNow;

            if (_state == CircuitState.HalfOpen)
            {
                Transition(CircuitState.Open, "test_call_failed");
                return;
            }

            if (_state == CircuitState.Closed && _failureCount >= _failureThreshold)
            {
                Transition(CircuitState.Open, "consecutive_failures");
            }
        }
    }

    /// <summary>The current circuit state.</summary>
    public CircuitState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>Returns diagnostics info.</summary>
    public CircuitBreakerDiagnostics GetDiagnostics()
    {
        lock (_lock)
        {
            var msUntilRecovery = TimeSpan.Zero;
            if (_state == CircuitState.Open)
            {
                var elapsed = DateTime.UtcNow - _lastFailureTime;
                msUntilRecovery = elapsed < _recoveryTime ? _recoveryTime - elapsed : TimeSpan.Zero;
            }

            var staleDuration = _staleSince is { } since ? DateTime.UtcNow - since : TimeSpan.Zero;

            return new CircuitBreakerDiagnostics(_state, _failureCount, _lastFailureTime, msUntilRecovery,
                staleDuration > StaleThreshold, staleDuration);
        }
    }

    /// <summary>Forces the circuit breaker back to the closed state.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            Transition(CircuitState.Closed, "manual_reset");
            _failureCount = 0;
            _lastFailureTime = DateTime.MinValue;
            _staleSince = null;
        }
    }

    /// <summary>Returns whether internal rules are stale (no platform sync for longer than <see cref="StaleThreshold"/>).</summary>
    public bool IsRulesStale()
    {
        lock (_lock)
        {
            return _staleSince is { } since && (DateTime.UtcNow - since) > StaleThreshold;
        }
    }

    private void Transition(CircuitState to, string reason)
    {
        var from = _state;
        if (from == to)
        {
            return;
        }
        _state = to;

        if (to == CircuitState.Open && _staleSince is null)
        {
            _staleSince = DateTime.UtcNow;
        }

        if (_onStateChange is not null)
        {
            try
            {
                _onStateChange(from, to, reason);
            }
            catch
            {
                // Callback errors should not break the circuit breaker.
            }
        }
    }
}
