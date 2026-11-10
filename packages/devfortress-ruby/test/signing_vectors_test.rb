# frozen_string_literal: true

require_relative "test_helper"

# The shared cross-language vectors (contracts/ingest-signature-vectors.json):
# the platform, the Node SDK, the Python SDK, the Go SDK, the PHP SDK and the
# open-core route all assert the same file.
class SigningVectorsTest < Minitest::Test
  def wire(vector)
    h = vector["headers"]
    {
      DevFortress::Signer::NONCE_HEADER => h["nonce"],
      DevFortress::Signer::TIMESTAMP_HEADER => h["timestamp"],
      DevFortress::Signer::PAYLOAD_HASH_HEADER => h["payload_hash"],
      DevFortress::Signer::SIGNATURE_HEADER => h["signature"],
      DevFortress::Signer::VERSION_HEADER => h["version"],
    }
  end

  def test_every_verifier_vector_gives_its_expected_result
    vectors = Vectors.ingest["vectors"]
    assert_operator vectors.length, :>=, 26
    vectors.each do |v|
      got = DevFortress::Signer.verify(
        v["verify_key"], v["method"], v["request_target"], v["body"], wire(v), now_ms: v["now_ms"]
      )
      assert_equal v["expected"], got, v["name"]
    end
  end

  def test_signing_matches_the_vectors_byte_for_byte
    signed_count = 0
    Vectors.ingest["vectors"].each do |v|
      next unless v["sign_input"] && %w[valid expired].include?(v["expected"])

      i = v["sign_input"]
      signed = DevFortress::Signer.new(i["api_key"]).sign(
        i["method"], i["request_target"], i["body"], timestamp: i["timestamp"], nonce: i["nonce"]
      )
      want = wire(v)
      assert_equal want[DevFortress::Signer::PAYLOAD_HASH_HEADER].downcase, signed[DevFortress::Signer::PAYLOAD_HASH_HEADER], v["name"]
      assert_equal want[DevFortress::Signer::SIGNATURE_HEADER].downcase, signed[DevFortress::Signer::SIGNATURE_HEADER], v["name"]
      assert_equal want[DevFortress::Signer::NONCE_HEADER], signed[DevFortress::Signer::NONCE_HEADER], v["name"]
      assert_equal want[DevFortress::Signer::TIMESTAMP_HEADER], signed[DevFortress::Signer::TIMESTAMP_HEADER], v["name"]
      assert_equal "2", signed[DevFortress::Signer::VERSION_HEADER]
      signed_count += 1
    end
    assert_operator signed_count, :>=, 8
  end

  def test_negative_vectors_do_not_match_what_the_signer_produces
    names = %w[different_path different_path_same_query different_method changed_query
               query_added prefix_stripped tampered_body wrong_key]
    seen = 0
    Vectors.ingest["vectors"].each do |v|
      next unless names.include?(v["name"])

      seen += 1
      w = wire(v)
      signed = DevFortress::Signer.new(v["verify_key"]).sign(
        v["method"], v["request_target"], v["body"],
        timestamp: w[DevFortress::Signer::TIMESTAMP_HEADER], nonce: w[DevFortress::Signer::NONCE_HEADER]
      )
      refute_equal w[DevFortress::Signer::SIGNATURE_HEADER], signed[DevFortress::Signer::SIGNATURE_HEADER], v["name"]
    end
    assert_equal names.length, seen
  end

  def test_key_id_derivation_matches_the_vectors
    vectors = Vectors.ingest["key_id_derivation"]["vectors"]
    assert_operator vectors.length, :>=, 3
    vectors.each do |v|
      assert_equal v["key_id"], DevFortress::Signer.derive_key_id(v["api_key"])
      assert_equal v["key_id"], DevFortress::Signer.new(v["api_key"]).key_id
    end
  end

  def test_signed_path_vector_headers_match_byte_for_byte
    checked = 0
    Vectors.ingest["signed_path_vectors"].each do |v|
      next unless v["sign_input"]

      i = v["sign_input"]
      signed = DevFortress::Signer.new(i["api_key"]).sign(
        i["method"], i["request_target"], i["body"], timestamp: i["timestamp"], nonce: i["nonce"]
      )
      h = v["headers"]
      assert_equal h["key_id"], signed[DevFortress::Signer::KEY_ID_HEADER], v["name"]
      assert_equal h["signature"], signed[DevFortress::Signer::SIGNATURE_HEADER], v["name"]
      assert_equal h["payload_hash"], signed[DevFortress::Signer::PAYLOAD_HASH_HEADER], v["name"]
      checked += 1
    end
    assert_operator checked, :>=, 4
  end

  # A reference server built only on Signer.verify, routing every
  # signed_path_vectors case the same way the platform does, proving the
  # verifier's output composes into the right accept/reject decision — not
  # just that individual fields match.
  def test_a_reference_server_built_on_the_verifier_agrees_with_every_signed_path_vector
    vectors = Vectors.ingest["signed_path_vectors"]
    assert_equal 18, vectors.length
    vectors.each do |v|
      h = v["headers"]
      key_id = h["key_id"].to_s

      if !key_id.empty? && !v["api_key_header"].nil?
        status, reason = 400, "ambiguous_credentials"
      else
        key = v["known_keys"].find { |candidate| DevFortress::Signer.derive_key_id(candidate) == key_id }
        result = if key.nil?
                   wire(v)[DevFortress::Signer::SIGNATURE_HEADER].nil? ? "missing" : "invalid"
                 else
                   DevFortress::Signer.verify(key, v["method"], v["request_target"], v["body"], wire(v), now_ms: v["now_ms"])
                 end
        status, reason = case result
                          when "valid" then [200, nil]
                          when "expired" then [400, "timestamp_expired"]
                          when "missing" then [401, "signature_missing"]
                          when "unsupported_version" then [401, "signature_version_unsupported"]
                          else [401, "signature_invalid"]
                          end
      end
      assert_equal v["expected"]["status"], status, v["name"]
      if v["expected"]["reason"].nil?
        assert_nil reason, v["name"]
      else
        assert_equal v["expected"]["reason"], reason, v["name"]
      end
    end
  end

  def test_request_target_is_the_path_and_query_as_written
    assert_equal "/api/events/ingest", DevFortress::Signer.request_target_from_url("https://www.devfortress.net/api/events/ingest")
    assert_equal "/gateway/api/x?v=1&x=a%20b", DevFortress::Signer.request_target_from_url("http://h:3001/gateway/api/x?v=1&x=a%20b#frag")
    assert_equal "/", DevFortress::Signer.request_target_from_url("http://h")
    assert_equal "/?a=1", DevFortress::Signer.request_target_from_url("http://h?a=1")
    assert_equal "/x?", DevFortress::Signer.request_target_from_url("http://h/x?")
    assert_equal "/a/../b", DevFortress::Signer.request_target_from_url("http://h/a/../b")
  end

  def test_nonce_is_a_dashed_v4_uuid
    pattern = /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/
    seen = {}
    50.times do
      n = DevFortress::Signer.uuid_v4
      assert_match pattern, n
      seen[n] = true
    end
    assert_equal 50, seen.length
  end
end
