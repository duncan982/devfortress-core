# frozen_string_literal: true

require "minitest/autorun"
require "json"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "devfortress"

# A scripted DevFortress::Transport double: each call to #send_request
# consumes the next script entry (a TransportResponse, or an exception
# instance to raise as a TransportError); the last entry repeats.
class ScriptedTransport
  attr_reader :requests

  def initialize(script)
    @script = script
    @requests = []
  end

  def send_request(method, url, headers, body, timeout)
    @requests << { method: method, url: url, headers: headers, body: body, timeout: timeout }
    step = @script[[@requests.length, @script.length].min - 1]
    raise DevFortress::TransportError, step.message if step.is_a?(Exception)

    step
  end
end

module Vectors
  # Reads a shared cross-language vector file from the repository's
  # contracts/ directory (../../contracts from this package), or from
  # DEVFORTRESS_CONTRACTS_DIR when set — same convention as the Go and PHP
  # SDKs' own test helpers.
  def self.dir
    ENV["DEVFORTRESS_CONTRACTS_DIR"] || File.expand_path("../../../contracts", __dir__)
  end

  def self.ingest
    @ingest ||= JSON.parse(File.read(File.join(dir, "ingest-signature-vectors.json")))
  end

  def self.webhook
    @webhook ||= JSON.parse(File.read(File.join(dir, "webhook-signature-vectors.json")))
  end
end
