from devfortress.agent_loop_detector import AgentLoopDetector


def test_within_limits_continues():
    d = AgentLoopDetector(max_cycles=20, max_duration_ms=120_000, max_tokens=100_000)
    r = d.record_cycle("agent-1", "s1", tool_name="search_products")
    assert r.action == "CONTINUE"
    assert r.loop is False


def test_max_cycles_without_progress_pauses():
    d = AgentLoopDetector(max_cycles=3, max_duration_ms=100_000)
    results = [d.record_cycle("agent-1", "s1", tool_name="same_tool", tool_args={"x": 1}) for _ in range(4)]
    assert results[2].action == "PAUSE_AGENT"
    assert results[2].loop is True
    assert results[3].action == "TERMINATE"  # already paused


def test_tool_diversity_counts_as_progress():
    d = AgentLoopDetector(max_cycles=3, max_duration_ms=100_000, progress_unique_tools=2, progress_window_cycles=5)
    tools = ["a", "b", "c", "a", "b"]
    results = [d.record_cycle("agent-1", "s1", tool_name=t) for t in tools]
    # Diverse tool usage keeps it making progress — never force-paused at 3 cycles.
    assert all(r.action != "PAUSE_AGENT" for r in results[:3])


def test_release_agent_resets_state():
    d = AgentLoopDetector(max_cycles=2, max_duration_ms=100_000)
    d.record_cycle("agent-1", "s1", tool_name="x")
    d.record_cycle("agent-1", "s1", tool_name="x")
    assert d.is_paused("s1") is True
    assert d.release_agent("s1") is True
    assert d.is_paused("s1") is False


def test_repetitive_args_flagged():
    d = AgentLoopDetector(max_cycles=20, max_duration_ms=100_000)
    for _ in range(8):
        r = d.record_cycle("agent-1", "s1", tool_name="x", tool_args={"same": "args"})
    assert r.repetition_score > 0.8
