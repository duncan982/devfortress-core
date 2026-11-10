# devfortress-sdk

The developer-first **Application and API security** SDK that stops attacks automatically — not just monitors them.

[![npm version](https://img.shields.io/npm/v/devfortress-sdk)](https://www.npmjs.com/package/devfortress-sdk)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](https://github.com/duncan982/devfortress/blob/main/packages/devfortress-sdk/LICENSE)

> 🛡️ **Patent Pending** — Core security architecture protected under provisional patent application.

## 🔒 Privacy First — What We Collect vs. What We Never Collect

| ✅ We Collect                        | ❌ We Never Collect                     |
| ------------------------------------ | --------------------------------------- |
| IP address (hashable in strict mode) | Request/response body content           |
| HTTP method & path                   | Cookies or session data                 |
| Status code & response time          | Authorization headers or tokens         |
| User agent (first 200 chars)         | Query string values or form data        |
| Timestamp                            | User PII (names, emails, phone numbers) |
| Session identifiers (anonymised)     | Real session tokens                     |
|                                      | Database queries or source code         |

> **Your real session tokens never leave your server.** DevFortress uses a proprietary aliasing mechanism — the platform never sees or stores your actual tokens. [Full transparency →](https://devfortress.net/privacy/data-collected)

## Installation

```bash
npm install devfortress-sdk
```

## The DevFortress Textbook

DevFortress implements 34 novel security inventions. Patent Pending.

These 34 inventions are documented in depth across 5 volumes.

**"Credential Isolation Closed-Loop Security"**
_Duncan Ndungu Ndegwa — DevFortress, 2026_

→ Available on Gumroad: [https://devfortress.gumroad.com/l/master-edition]

## ⚡ Zero-Config Quick Start (under 3 minutes)

```bash
npx devfortress-init
```

Or one line in your code:

```typescript
import df from 'devfortress-sdk/quick';
df.init({ apiKey: 'df_your_key' });
```

### Privacy-Strict Mode

```typescript
df.init({ apiKey: 'df_...', privacy: 'strict' });
// IPs are SHA-256 hashed before sending, user agents omitted
```

### Debug Mode — See Exactly What's Sent

```typescript
df.init({ apiKey: 'df_...', debug: true });
// Console: [DF →] DevFortress initialized (framework: express, privacy: standard)
```

### Data Snapshot — Inspect Before Sending

```typescript
import { getDataSnapshot } from 'devfortress-sdk/quick';
console.log(getDataSnapshot(req));
// { collected: { ip, method, path, ... }, neverCollected: ['Request body', ...] }
```

## Quick Start

### Express.js Middleware (Automatic)

```typescript
import express from 'express';
import { devfortressMiddleware } from 'devfortress-sdk';

const app = express();

// Add DevFortress monitoring — automatically detects threats
app.use(
  devfortressMiddleware({
    apiKey: process.env.DEVFORTRESS_API_KEY!,
  })
);

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);
```

### Manual Event Tracking (Node.js)

```typescript
import { DevFortressClient } from 'devfortress-sdk';

const client = new DevFortressClient({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
});

// Track a security event
await client.trackEvent({
  eventType: 'auth_failure',
  ip: req.ip || '0.0.0.0',
  userAgent: req.get('user-agent'),
  metadata: {
    username: req.body.username,
    reason: 'invalid_password',
  },
});
```

### Browser Client

```typescript
import { DevFortressBrowserClient } from 'devfortress-sdk/browser';

const client = new DevFortressBrowserClient({
  apiKey: 'your-publishable-key', // Use a PUBLIC/scoped key — visible in DevTools
});

// Install global error handler
const cleanup = client.installGlobalErrorHandler();

// Track API failures
client.trackApiFailure('/api/data', 500, 'GET');

// Cleanup when done
cleanup();
```

> ⚠️ **Browser Security Notice:** The API key is visible to end users via browser DevTools. Use a scoped/publishable key with limited permissions — never use your secret admin key in browser builds.

## Features

- 🚀 **Zero-config Express.js middleware** — automatic threat detection
- 🔒 **Pattern detection** — SQL injection, XSS, path traversal, brute force
- 📊 **Real-time security insights** — events stream to your DevFortress dashboard
- ⚡ **Non-blocking** — async event capture, never slows your API
- 🎯 **Custom event tracking** — send any security-relevant event
- 🌐 **Multi-platform** — Node.js, Browser, Express, FastAPI, Flask
- 🔧 **Type-safe** — full TypeScript support with exported types
- 🤖 **Agent Security (v3.2)** — observe AI agent tool calls, per-agent credential isolation, behavioral baselines, anomaly detection, scope enforcement
- 🔑 **Session Privacy** — Encrypted session identifiers, secure reverse-lookup, fallback cache
- 🛡️ **Closed-Loop Response** — automatic threat detection → block → webhook notification → action report
- 🏭 **Internal Mode (v3.3)** — Sub-millisecond inline protection with air-gap mode and zero external dependencies
- 🔄 **Hybrid Mode (v4.0)** — Local evaluation first, external enrichment with automatic failover
- ⚡ **Resilient Failover (v4.0)** — Automatic failover for hybrid mode resilience
- 🎫 **Tier Gating (v4.0)** — Starter/Pro/Enterprise subscription enforcement: modes, blocking, event limits at SDK level
- 📋 **Unified Audit Trail (v4.0)** — single timeline merging internal/external/hybrid decisions with stats, histograms, export

## 🤖 AI Agent Security (v3.2)

Protect AI agents (LangChain, OpenAI, Anthropic, custom) from prompt injection, credential theft, and scope escalation.

### Agent Tool Observability

```typescript
import { DevFortress, AgentAdapter } from 'devfortress-sdk';

const df = new DevFortress({ apiKey: process.env.DEVFORTRESS_API_KEY! });
const agent = new AgentAdapter(df, {
  agentId: 'research-agent',
  agentName: 'Research Assistant',
  sanitizeInputs: true, // Auto-redact keys/tokens/secrets
  onFlagged: (toolCall, result) => {
    console.error(`Tool ${toolCall.tool} flagged: risk=${result.riskScore}`);
  },
});

// LangChain integration
await agent.observeLangChainTool(
  'web_search',
  { query: 'test' },
  { model: 'gpt-4o' }
);

// OpenAI function calling
await agent.observeOpenAIToolCall({
  function: { name: 'get_weather', arguments: '{"location":"London"}' },
});

// Raw HTTP tool call
await agent.observeHttpToolCall('https://api.example.com/data', 'POST', {
  statusCode: 200,
  durationMs: 150,
});
```

### Agent Credential Isolation

```typescript
import { DevFortress } from 'devfortress-sdk';

const df = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  mode: 'internal',
  tier: 'enterprise',
});

// Isolate agent credentials — real keys never leave your server
const alias = await df.isolateCredential('sk-real-api-key-here', 'agent-1');

// Quarantine an agent (preserves session for forensics)
await df.quarantineAgent('agent-1', 'Suspicious tool usage');

// Full revocation — compromised agent
await df.revokeAgentAccess('agent-1', 'active_threat');
```

### Behavioral Baseline & Anomaly Detection

```typescript
import { DevFortress } from 'devfortress-sdk';

const df = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  tier: 'enterprise',
});

// Register handler for anomalies
df.onAnomaly((signal) => {
  if (signal.severity === 'critical') {
    // Auto-quarantine agent on critical anomaly
    df.quarantineAgent(signal.agentId, signal.description);
  }
});

// Record sessions to build baseline (auto after 5 sessions)
df.recordSession({ agentId: 'agent-1', sessionId: 's1', toolCalls: [...] });

// Detect anomalies per tool call
const signals = df.analyzeToolCall('agent-1', 'delete_database', 1_000_000);
// → [{ type: 'scope_deviation', severity: 'medium' },
//    { type: 'data_volume_anomaly', severity: 'high' }]
```

### Scope Enforcement (Prompt Injection Defence)

```typescript
import { DevFortress } from 'devfortress-sdk';

const df = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  tier: 'enterprise',
});

// Define what tools an agent is allowed to use
df.defineAgentScope('agent-1', ['web_search', 'calculator', 'format'], true);

// Check before execution
if (!df.isToolAllowed('agent-1', 'shell_exec')) {
  // CRITICAL: unsanctioned tool — likely prompt injection
  // The anomaly detector also fires this automatically
}
```

## Configuration

### Middleware Options

```typescript
interface DevFortressMiddlewareOptions {
  apiKey: string; // Required: Your DevFortress API key
  endpoint?: string; // Default: https://www.devfortress.net/api/events/ingest
  captureBody?: boolean; // Default: false — capture request body
  captureHeaders?: boolean; // Default: false — capture request headers
  excludePaths?: string[]; // Paths to exclude from monitoring (e.g. ['/health'])
  sanitize?: (data) => data; // Sanitize metadata before sending
  onRequest?: (req) => event; // Custom event detection callback
  onError?: (error) => void; // Error handler for failed event sends
  timeout?: number; // Request timeout in ms (default: 5000)
  retries?: number; // Retry failed requests (default: 3)
}
```

> ⚠️ **Privacy Warning:** When `captureHeaders` is `true`, headers including `Authorization`, `Cookie`, and session tokens are sent to DevFortress. When `captureBody` is `true`, raw request bodies (which may contain passwords, credit cards, etc.) are captured. Always use the `sanitize` callback to strip sensitive data.

### Client Options

```typescript
interface DevFortressClientOptions {
  apiKey: string; // Required: Your DevFortress API key
  endpoint?: string; // Default: https://www.devfortress.net/api/events/ingest
  timeout?: number; // Request timeout in ms (default: 5000)
  retries?: number; // Retry count (default: 3, exponential backoff)
  debug?: boolean; // Enable debug logging (default: false)
}
```

## Event Types

The SDK automatically detects and reports:

| Event Type              | Description                        | Auto-Detected |
| ----------------------- | ---------------------------------- | ------------- |
| `auth_failure`          | Failed authentication (401/403)    | ✅            |
| `validation_error`      | Input validation errors (400/422)  | ✅            |
| `rate_limit_exceeded`   | Rate limit violations (429)        | ✅            |
| `5xx_error`             | Server errors                      | ✅            |
| `4xx_error`             | Client errors                      | ✅            |
| `suspicious_pattern`    | SQL injection, XSS, path traversal | ✅            |
| `sql_injection_attempt` | SQL injection detected             | Manual        |
| `xss_attempt`           | XSS attack detected                | Manual        |
| `custom`                | Any custom security event          | Manual        |

## Python Middleware

### FastAPI / Starlette

Copy `src/middleware/fastapi.py` into your project:

```python
from devfortress_middleware import DevFortressMiddleware

app = FastAPI()
app.add_middleware(
    DevFortressMiddleware,
    api_key="your-api-key",
    endpoint="https://www.devfortress.net/api/events/ingest"
)
```

### Flask

Copy `src/middleware/flask.py` into your project:

```python
from devfortress_middleware import DevFortressFlask

app = Flask(__name__)
devfortress = DevFortressFlask(
    app,
    api_key="your-api-key",
    endpoint="https://www.devfortress.net/api/events/ingest"
)
```

## Security Best Practices

1. **API Key Management** — Store keys in environment variables, never commit them
2. **Header/Body Capture** — Both default to `false`. Enable only with a `sanitize` callback
3. **Browser Keys** — Use scoped/publishable keys for browser builds (visible in DevTools)
4. **HTTPS Only** — The SDK warns if a non-HTTPS endpoint is configured
5. **Error Handling** — Implement `onError` to prevent monitoring failures from affecting your API
6. **Rate Limiting** — SDK respects rate limits (1000 events/minute per project)

## Advanced Usage

### Custom Threat Detection

```typescript
app.use(
  devfortressMiddleware({
    apiKey: process.env.DEVFORTRESS_API_KEY!,
    onRequest: req => {
      // Custom threat detection logic
      if (isCustomThreat(req)) {
        return {
          eventType: 'custom',
          severity: 'HIGH',
          reason: 'Custom rule triggered',
        };
      }
      return null;
    },
  })
);
```

### Sanitizing Sensitive Data

```typescript
app.use(
  devfortressMiddleware({
    apiKey: process.env.DEVFORTRESS_API_KEY!,
    captureBody: true,
    captureHeaders: true,
    sanitize: data => {
      // Strip sensitive fields before sending to DevFortress
      const sanitized = { ...data };
      if (sanitized.body) {
        delete (sanitized.body as Record<string, unknown>).password;
        delete (sanitized.body as Record<string, unknown>).creditCard;
      }
      if (sanitized.headers) {
        delete (sanitized.headers as Record<string, unknown>).authorization;
        delete (sanitized.headers as Record<string, unknown>).cookie;
      }
      return sanitized;
    },
  })
);
```

## Required Endpoints

The SDK communicates with these DevFortress platform endpoints (all must be accessible):

| Endpoint                   | Method   | Purpose                  |
| -------------------------- | -------- | ------------------------ |
| `/api/events/ingest`       | POST     | Send security events     |
| `/api/events/blocked`      | GET      | Check if IP is blocked   |
| `/api/events/action-taken` | POST     | Report actions taken     |
| `/api/events/test-ips`     | GET/POST | Manage test IP whitelist |

Base URL: `https://www.devfortress.net`

> **Note:** In Internal mode (`mode: 'internal'`), no external endpoints are called. In Hybrid mode, endpoints are called only for allowed traffic with automatic failover to local-only processing.

## 🔄 Three-Mode Closed-Loop (v4.0)

SDK v4.0.0 introduces three closed-loop protection modes:

```typescript
import { DevFortress } from 'devfortress-sdk';

// External mode — cloud-based analysis (default for Starter/Pro)
const dfExternal = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  mode: 'external',
  tier: 'pro',
});

// Internal mode — zero network calls per request (Team tier and above)
const dfInternal = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  mode: 'internal',
  tier: 'team',
});

// Hybrid mode — local first, cloud enrichment with automatic failover (Team tier and above; air-gap is Enterprise-only)
const dfHybrid = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'my-app',
  mode: 'hybrid',
  tier: 'enterprise',
});

// All modes use the same observe() API
const result = await dfHybrid.observe({
  ip: '1.2.3.4',
  endpoint: '/api/users',
});

// Unified audit trail — one view across all modes
const stats = dfHybrid.getAudit().getStats();
// { internalDecisions, externalDecisions, hybridDecisions, fallbackEvents, ... }
```

## Testing Your Integration

See the full [SDK Integration Guide](https://github.com/duncan982/devfortress/blob/main/docs/sdk-integration-guide.md) for step-by-step testing and troubleshooting.

## Pricing

| Tier             | Flagged Events/Month |         Automated Actions          | Retention |
| ---------------- | :------------------: | :--------------------------------: | :-------: |
| Starter ($29/mo) |         50K          | Webhook-dispatched (self-executed) |  7 days   |
| Pro ($69/mo)     |         75K          |               500/mo               |  30 days  |
| Team ($149/mo)   |         100K         |              5,000/mo              |  1 year   |

Billing counts only flagged/scored events, not raw SDK-observed traffic.

## Publishing (maintainers only)

1. Bump the version and run `npm publish` (this repo's `prepublishOnly`
   script automatically builds and runs `verify:package`'s require-graph
   check first).
2. **After** the publish completes, run
   `npm run smoke-test:published` (or `bash scripts/smoke-test-published.sh [version]`)
   to install the just-published version fresh from the real npm registry
   into a scratch directory and confirm it `require()`/`import`s cleanly.
   This step is manual and intentionally not part of `prepublishOnly` or any
   build/CI step — it can only run against a version that is already live
   on the registry, and is not a substitute for verifying workspace-linked
   consumers separately.
3. If you also maintain another registry-installed consumer application,
   bump its pin to the new version and re-run its own smoke test in the
   same session rather than leaving it on a stale pin.

## License

BUSL-1.1 © DevFortress (devfortress.net)

See [LICENSE](./LICENSE) for details. The Change License is Apache-2.0, effective 2030-01-01.
