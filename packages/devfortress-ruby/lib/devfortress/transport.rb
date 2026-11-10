# frozen_string_literal: true

require "net/http"
require "uri"

module DevFortress
  TransportResponse = Struct.new(:status_code, :body, keyword_init: true)

  class TransportError < StandardError; end

  # The default transport: Net::HTTP, no redirects followed, path sent as written.
  class Transport
    def send_request(method, url, headers, body, timeout)
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.write_timeout = timeout if http.respond_to?(:write_timeout=)

      request = Net::HTTP.const_get(method.to_s.capitalize).new(uri.request_uri)
      headers.each { |k, v| request[k] = v }
      request.body = body if body && !body.empty?

      response = http.request(request)
      TransportResponse.new(status_code: response.code.to_i, body: response.body.to_s)
    rescue StandardError => e
      raise TransportError, e.message
    end
  end
end
