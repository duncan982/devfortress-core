# frozen_string_literal: true

require_relative "test_helper"

class ClassifierTest < Minitest::Test
  def test_encoded_sql_injection_is_flagged
    assert_includes DevFortress::Classifier.detect_suspicious("/search q=1%27%20OR%20%271%27%3D%271"), "sql_injection"
    assert_includes DevFortress::Classifier.detect_suspicious("/search q=1+UNION+SELECT+password+FROM+users"), "sql_injection"
  end

  def test_encoded_xss_and_traversal_are_flagged
    assert_includes DevFortress::Classifier.detect_suspicious("/x q=%3Cscript%3Ealert(1)%3C/script%3E"), "xss"
    assert_includes DevFortress::Classifier.detect_suspicious("/x f=..%2F..%2Fetc%2Fpasswd"), "path_traversal"
  end

  def test_a_literal_percent_is_not_flagged
    assert_equal [], DevFortress::Classifier.detect_suspicious("/search q=100% organic")
    assert_equal [], DevFortress::Classifier.detect_suspicious("/discount code=SAVE20%")
  end

  def test_double_encoded_input_is_handled_without_error_and_not_detected
    # One decoding pass only: %2527 becomes %27, not a quote. A known limit.
    assert_equal [], DevFortress::Classifier.detect_suspicious("/x q=%2527%2520OR%2520%25271%2527%253D%25271")
  end

  def test_raw_matching_is_unchanged
    assert_equal ["sql_injection"], DevFortress::Classifier.detect_suspicious("/x q=' or '1'='1")
    assert_equal [], DevFortress::Classifier.detect_suspicious("/plain")
  end

  def test_invalid_utf8_does_not_raise
    assert_equal [], DevFortress::Classifier.detect_suspicious("/x q=\xff\xfe".dup.force_encoding("UTF-8"))
  end

  def test_event_shape_mirrors_the_other_sdks
    assert_nil DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "GET", path: "/ok", status_code: 200, latency_ms: 5)

    auth = DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "GET", path: "/secret", status_code: 401, latency_ms: 5, user_agent: "ua")
    assert_equal "auth_failure", auth["eventType"]
    assert_equal "MEDIUM", auth["severity"]
    assert_equal "blocked", auth["actionTaken"]
    assert_equal "external", auth["clMode"]
    assert_equal "pre_auth", auth["authPhase"]
    assert_equal({ "reason" => "Authentication or authorization failed" }, auth["metadata"])

    limit = DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "GET", path: "/x", status_code: 429, latency_ms: 5)
    assert_equal ["rate_limit_exceeded", "rate_limited"], [limit["eventType"], limit["actionTaken"]]

    server = DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "GET", path: "/x", status_code: 503, latency_ms: 5, user_id: "u1")
    assert_equal ["5xx_error", "HIGH", "post_auth"], [server["eventType"], server["severity"], server["authPhase"]]

    not_found = DevFortress::Classifier.build_event(ip: "", method: "GET", path: "/x", status_code: 404, latency_ms: 5)
    assert_equal ["4xx_error", "LOW", "0.0.0.0"], [not_found["eventType"], not_found["severity"], not_found["ip"]]

    bad = DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "POST", path: "/x", status_code: 422, latency_ms: 5)
    assert_equal "validation_error", bad["eventType"]
  end

  def test_a_suspicious_request_overrides_the_status_classification
    event = DevFortress::Classifier.build_event(ip: "203.0.113.7", method: "GET", path: "/", status_code: 200, latency_ms: 5, query: "q=1%27%20OR%20%271%27=%271")
    assert_equal "suspicious_pattern", event["eventType"]
    assert_equal "HIGH", event["severity"]
    assert_equal "flagged", event["actionTaken"]
    assert_equal({ "reason" => "Suspicious patterns detected: sql_injection" }, event["metadata"])
  end
end
