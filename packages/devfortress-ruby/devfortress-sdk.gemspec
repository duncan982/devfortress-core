require_relative "lib/devfortress/version"

Gem::Specification.new do |spec|
  spec.name          = "devfortress-sdk"
  spec.version       = DevFortress::VERSION
  spec.authors       = ["Duncan Ndungu Ndegwa"]
  spec.summary       = "DevFortress Security SDK"
  spec.description   = "Event reporting client for DevFortress (external mode): request " \
                        "signing, classification and webhook verification for Ruby " \
                        "applications (Rails, Rack, Sinatra). Pre-release, not published."
  spec.homepage      = "https://github.com/duncan982/devfortress-core/tree/main/packages/devfortress-ruby"
  spec.license       = "BUSL-1.1"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["homepage_uri"] = spec.homepage

  # tier2_gated/ (A19C agent-identity protection, plus B3 ConsentAliasLifecycle
  # and B4 MultiHopTrustChain as of TODO 420, 2026-11-03) and internal.rb (its
  # only entry point) are PATENT-GATE'd — excluded from the published
  # gem, mirroring the Node SDK package.json's
  # `!dist/consent-alias-lifecycle.*`/`!dist/multi-hop-trust-chain.*`/
  # `!dist/agent-identity/**`/`!dist/internal.js` exclusions. A normal
  # `gem install devfortress-sdk` never has these files on disk; see
  # lib/devfortress/internal.rb's own comment for the second
  # (private_constant, A19C-only) layer that holds even if this one is
  # bypassed (e.g. a vendored/monorepo-internal require of the source).
  #
  # TODO 420 reversed TODO 367/382's 2026-10-16/17 decision to ship B3/B4
  # public: that decision assumed Node already shipped them public, but
  # commit 4a3e71e3 (2026-10-06) had already excluded them from Node's npm
  # tarball ten days earlier. Duncan's resolution: match Node's actual
  # excluded state.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features)/}) ||
        f.match(%r{^lib/devfortress/tier2_gated/}) ||
        f == "lib/devfortress/internal.rb" ||
        f == File.basename(__FILE__)
    end
  end
  spec.require_paths = ["lib"]

  # Stdlib only (net/http, openssl, digest, json, securerandom, ipaddr) —
  # matching the Go SDK's stdlib-only core and the PHP SDK's minimal-
  # dependency approach. No runtime gem dependency.
  spec.add_development_dependency "minitest", "~> 5.16"
  # Test-only, for a real local HTTP stub server in abuseipdb_test.rb
  # (net/http itself is stdlib and already used by lib/devfortress).
  spec.add_development_dependency "webrick", "~> 1.8"
end
