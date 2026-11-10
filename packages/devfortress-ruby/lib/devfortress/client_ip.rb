# frozen_string_literal: true

require "ipaddr"

module DevFortress
  # Picks the end-user IP for an event from what the request shows.
  #
  # Precedence: first X-Forwarded-For entry, then X-Real-IP, then the socket
  # address, then 0.0.0.0. A candidate that is not an IP address is skipped, so a
  # malformed forwarded header cannot poison a batch.
  module ClientIp
    def self.resolve(forwarded_for, real_ip, remote_addr)
      first = forwarded_for.nil? ? "" : forwarded_for.split(",").first.to_s.strip
      [first, real_ip.to_s.strip, remote_addr.to_s.strip].each do |candidate|
        return candidate if !candidate.empty? && ip?(candidate)
      end
      "0.0.0.0"
    end

    def self.ip?(candidate)
      IPAddr.new(candidate)
      true
    rescue IPAddr::Error
      false
    end
    private_class_method :ip?
  end
end
