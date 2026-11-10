# DevFortress Rails Adapter

Rails integration for the [DevFortress Ruby SDK](https://github.com/duncan982/devfortress-core/tree/main/packages/devfortress-ruby):
a Railtie that inserts a Rack middleware into your app's middleware stack
automatically, configured from `Rails.application.config`.

## Install

```ruby
gem "devfortress-sdk-rails"
```

## Configure

```ruby
# config/application.rb or an initializer
config.devfortress = {
  api_key: ENV["DEVFORTRESS_API_KEY"],
  endpoint: ENV["DEVFORTRESS_ENDPOINT"], # optional, defaults to the DevFortress platform
  exclude_paths: %w[/health /up],        # optional, these are the defaults
}
```

The Railtie only activates once `api_key` is set — with no key configured it's a no-op,
so it's safe to require even in environments that don't set one.

## What it reports

Each request's method, path, status, timing, client IP and classifier result, via
`DevFortress::Observer.observe_and_flush` (not the sparse-traffic-unsafe `.observe`) so a
single request under low traffic is still delivered, not left queued.

## Tests

```
bundle exec rake test
```

License: BUSL-1.1
