# DevFortress ASP.NET Core Middleware

ASP.NET Core integration for the [DevFortress .NET SDK](https://github.com/duncan982/devfortress-core/tree/main/packages/devfortress-dotnet):
middleware that observes each request and reports a security event for it after the
response has been sent.

## Install

```xml
<PackageReference Include="DevFortress.AspNetCore" Version="0.1.0" />
```

## Configure

```csharp
app.UseDevFortress(client, options =>
{
    options.ExcludePaths = ["/health", "/up"]; // default
    options.InspectRequestBody = false;         // default — see XML docs for the tradeoff
});
```

## What it reports

Each request's method, path, status, timing, client IP and classifier result, via
`try`/`finally` around `next(context)` so a request is still reported even when an
unhandled exception propagates out of the pipeline — `HttpResponse.OnCompleted` does not
fire on that path, which an earlier version of this middleware relied on and a regression
test now guards against. Delivery uses `Observer.ObserveAndFlush`, not `Observer.Observe`,
so a single request is delivered even under sparse traffic.

## Tests

```
dotnet test
```

License: BUSL-1.1
