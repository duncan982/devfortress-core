# frozen_string_literal: true

module DevFortress
  DeliveryResult = Struct.new(:ok, :status_code, :body, :error, :attempts, keyword_init: true) do
    def ok?
      ok
    end
  end
end
