# frozen_string_literal: true

require "minitest/autorun"
require "rack/test"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
$LOAD_PATH.unshift(File.expand_path("../../devfortress-ruby/lib", __dir__))
require "devfortress/rails"

# Mirrors DevFortress::Transport's interface; records every call so tests can
# assert on delivery without hitting the network.
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
