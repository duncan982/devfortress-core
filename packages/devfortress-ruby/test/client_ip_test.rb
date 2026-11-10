# frozen_string_literal: true

require_relative "test_helper"

class ClientIpTest < Minitest::Test
  def test_precedence_is_forwarded_for_then_real_ip_then_socket
    assert_equal "203.0.113.9", DevFortress::ClientIp.resolve("203.0.113.9, 10.0.0.1", "198.51.100.1", "192.0.2.1")
    assert_equal "198.51.100.1", DevFortress::ClientIp.resolve(nil, "198.51.100.1", "192.0.2.1")
    assert_equal "192.0.2.1", DevFortress::ClientIp.resolve("", "", "192.0.2.1")
    assert_equal "0.0.0.0", DevFortress::ClientIp.resolve(nil, nil, nil)
  end

  def test_an_entry_that_is_not_an_ip_is_skipped
    assert_equal "198.51.100.1", DevFortress::ClientIp.resolve("unknown", "198.51.100.1", "192.0.2.1")
    assert_equal "2001:db8::1", DevFortress::ClientIp.resolve("2001:db8::1", nil, nil)
    assert_equal "0.0.0.0", DevFortress::ClientIp.resolve("<script>", "nope", "x")
  end
end
