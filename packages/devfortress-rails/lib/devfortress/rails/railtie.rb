# frozen_string_literal: true

# Loaded only when running inside an actual Rails app (Rails itself isn't a
# dependency of this gem — see the gemspec). Inserts Middleware into the
# middleware stack automatically, configured from Rails.application.config.
if defined?(::Rails::Railtie)
  module DevFortress
    module Rails
      class Railtie < ::Rails::Railtie
        initializer "devfortress.middleware" do |app|
          config = app.config.respond_to?(:devfortress) ? app.config.devfortress : nil
          api_key = (config && config[:api_key]) || ENV["DEVFORTRESS_API_KEY"]
          next unless api_key && !api_key.empty?

          client = DevFortress::Client.new(
            api_key,
            (config && config[:endpoint]) || ENV["DEVFORTRESS_ENDPOINT"] || DevFortress::Client::DEFAULT_ENDPOINT,
            defaults: (config && config[:defaults]) || {},
          )
          exclude_paths = (config && config[:exclude_paths]) || %w[/health /up]
          app.middleware.use DevFortress::Rails::Middleware, client: client, exclude_paths: exclude_paths
        end
      end
    end
  end
end
