# frozen_string_literal: true

module DevFortress
  WebhookVerification = Struct.new(:valid, :reason) do
    def valid?
      valid
    end
  end
end
