from devfortress.classify import detect_suspicious


def test_encoded_sqli_is_flagged():
    assert "sql_injection" in detect_suspicious("/search q=1%27%20OR%20%271%27%3D%271")
    assert "sql_injection" in detect_suspicious("/search q=1+UNION+SELECT+password+FROM+users")


def test_encoded_xss_and_traversal_flagged():
    assert "xss" in detect_suspicious("/x q=%3Cscript%3Ealert(1)%3C/script%3E")
    assert "path_traversal" in detect_suspicious("/x f=..%2F..%2Fetc%2Fpasswd")


def test_literal_percent_is_not_flagged():
    assert detect_suspicious("/search q=100% organic") == []
    assert detect_suspicious("/discount code=SAVE20%") == []


def test_double_encoded_is_handled_without_error():
    # One decoding pass only: %2527 -> %27, not a quote. Not detected (known limit).
    assert detect_suspicious("/x q=%2527%2520OR%2520%25271%2527%253D%25271") == []


def test_raw_matching_unchanged():
    assert detect_suspicious("/x q=' or '1'='1") == ["sql_injection"]
    assert detect_suspicious("/plain") == []
