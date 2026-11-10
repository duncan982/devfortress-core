from devfortress.tool_call_sequence_validator import ToolCallGraphNode, ToolCallSequenceValidator

GRAPH = {
    "search_products": ToolCallGraphNode(requires=[]),
    "add_to_cart": ToolCallGraphNode(requires=["search_products"]),
    "place_order": ToolCallGraphNode(requires=["add_to_cart"], risk_level="critical"),
}


def test_valid_sequence_allowed():
    v = ToolCallSequenceValidator(GRAPH)
    r1 = v.validate("s1", "search_products")
    assert r1.allowed is True
    r2 = v.validate("s1", "add_to_cart")
    assert r2.allowed is True


def test_out_of_sequence_blocked_and_flagged_as_prompt_injection():
    v = ToolCallSequenceValidator(GRAPH)
    r = v.validate("s1", "place_order")
    assert r.allowed is False
    assert r.reason == "out_of_sequence"
    assert r.prompt_injection_likely is True  # place_order is risk_level=critical


def test_unknown_tool_rejected():
    v = ToolCallSequenceValidator(GRAPH)
    r = v.validate("s1", "nonexistent_tool")
    assert r.allowed is False
    assert r.reason == "unknown_tool"


def test_max_calls_exceeded():
    graph = {"once_only": ToolCallGraphNode(requires=[], max_calls=1)}
    v = ToolCallSequenceValidator(graph)
    r1 = v.validate("s1", "once_only")
    assert r1.allowed is True
    r2 = v.validate("s1", "once_only")
    assert r2.allowed is False
    assert r2.reason == "max_calls_exceeded"


def test_graduated_response_escalates_with_violations():
    v = ToolCallSequenceValidator(GRAPH, max_violations=3)
    actions = [v.validate("s1", "place_order").action for _ in range(4)]
    assert actions == ["rate_limit", "block", "revoke_session", "revoke_session"]


def test_reset_session_clears_history():
    v = ToolCallSequenceValidator(GRAPH)
    v.validate("s1", "search_products")
    assert v.get_history("s1") == ["search_products"]
    v.reset_session("s1")
    assert v.get_history("s1") == []
