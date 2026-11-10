require_relative "lib/devfortress/rails/version"

Gem::Specification.new do |spec|
  spec.name          = "devfortress-sdk-rails"
  spec.version       = DevFortress::Rails::VERSION
  spec.authors       = ["Duncan Ndungu Ndegwa"]
  spec.summary       = "DevFortress Security SDK — Rails / Rack adapter"
  spec.description   = "Rack middleware adapter for the DevFortress Ruby SDK (devfortress-sdk): " \
                        "observes requests under Rails, Sinatra or any other Rack app, and " \
                        "reports security events for them. Pre-release, not published."
  spec.homepage      = "https://github.com/duncan982/devfortress-core/tree/main/packages/devfortress-rails"
  spec.license       = "BUSL-1.1"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["homepage_uri"] = spec.homepage

  spec.files         = Dir.chdir(File.expand_path("..", __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "devfortress-sdk", "0.1.0"
  spec.add_dependency "rack", ">= 2.0"

  spec.add_development_dependency "minitest", "~> 5.16"
  spec.add_development_dependency "rack-test", "~> 2.1"
end
