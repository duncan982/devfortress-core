# DevFortress Spring Boot Adapter

Spring Boot integration for the [DevFortress Java SDK](https://github.com/duncan982/devfortress-core/tree/main/packages/devfortress-java):
a servlet filter (`DevFortressFilter`) that observes each request and reports a
security event for it after the response has been sent.

## Install

```xml
<dependency>
  <groupId>net.devfortress</groupId>
  <artifactId>devfortress-spring-boot</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Configure

Register `DevFortressFilter` as a Spring bean, backed by a `net.devfortress.Client`
constructed the same way as the plain Java SDK (API key + endpoint).

## What it reports

Each request's method, path, status, timing, client IP and classifier result.
Reporting happens in a `finally` block after `filterChain.doFilter(...)` returns, via
`Observer.observeAndFlush` (not `.observe`), so a single request is delivered even under
sparse traffic — the same fix the Rails and Laravel adapters ship from the start.

## Tests

```
mvn test
```

License: BUSL-1.1
