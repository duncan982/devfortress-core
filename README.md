# DevFortress — Open-Core Security Platform

![Patent Pending](https://img.shields.io/badge/Patent-Pending-blue)
![License](https://img.shields.io/badge/License-BUSL--1.1-green)
![npm](https://img.shields.io/npm/v/devfortress-sdk)

**DevFortress** is a developer-first security platform for APIs, applications,
and AI agents. It implements the **Token-Aliased Closed-Loop Security**
architecture — real-time threat classification and automated response via
HMAC-signed webhook callbacks, with real credentials never leaving your
infrastructure.

## SDK — Install via npm

The DevFortress SDK is distributed exclusively via npm.
There is no SDK source in this repository.

```bash
npm install devfortress-sdk
```

```typescript
import { DevFortress } from 'devfortress-sdk';

const df = new DevFortress({
  apiKey: process.env.DEVFORTRESS_API_KEY!,
  appId: 'your-app-id',
  mode: 'hybrid',
  specialization: {
    app_security: true,
    api_key_aliasing_service: true,
  },
});

export async function middleware(request: NextRequest) {
  await df.observe(request);
  return NextResponse.next();
}
```

Full documentation: [devfortress.net/docs](https://devfortress.net/docs)

## What's in this repository

This repository contains the **open platform layer** — the interfaces,
schemas, and UI that the npm-installed SDK communicates with.

| Path                       | Description                             |
| -------------------------- | --------------------------------------- |
| `app/api/events/ingest/`   | Event ingestion interface               |
| `app/api/sdk/credentials/` | SDK credential management interface     |
| `app/collect/`             | Collect phase UI                        |
| `prisma/migrations/`       | Database schema — PostgreSQL migrations |

The hosted platform — LEARN phase, Platform Intelligence (B1–B12), threat
classifiers, and the blocking decision engine — is proprietary and available
via [devfortress.net](https://devfortress.net).

## SDK Specialization Modes

| Mode                       | Description                             | Availability |
| -------------------------- | --------------------------------------- | ------------ |
| `app_security`             | Baseline API and application protection | All tiers    |
| `api_key_aliasing_service` | A19 — credential aliasing and rotation  | Pro+         |
| `account_takeover_defense` | A5, A6, A11–A15 bundle                  | Pro+         |
| `commerce_abuse_defense`   | A14 + anti-fraud controls               | Pro+         |
| `ai_agent_security`        | A7, A10, A16, A17 — agentic detection   | Pro+         |
| `llm_protection`           | Prompt injection and output security    | Enterprise   |
| `mcp_protection`           | MCP protocol security and audit         | Enterprise   |
| `fintech_security`         | PCI-DSS, transaction monitoring         | Enterprise   |
| `healthcare_security`      | HIPAA, PHI detection                    | Enterprise   |
| `web3_protection`          | Wallet and smart contract protection    | Enterprise   |

## Contributing

**This repository does not accept pull requests or external code contributions.**

The platform layer shown here is maintained solely by the core team. The SDK
is closed-source and distributed via npm — there is no source to contribute to
in this repository.

You are welcome to:

- Open a **GitHub Issue** to report a bug or request a feature
- Email security@devfortress.net for responsible vulnerability disclosure —
  do not open public issues for security vulnerabilities
- Star and watch the repo for updates

This policy will be revisited as the project matures.

## License

Open platform layer: [BUSL-1.1](https://mariadb.com/bsl11/)
SDK and platform intelligence layer: Proprietary — All rights reserved

## Patent Notice

Token Alias Security, Closed-Loop Automated Response, and Platform
Intelligence are Patent Pending — KIPI KE/P/2026/005970–005973.

Prior art defensively published:

- [Zenodo — Filing 1](https://doi.org/10.5281/zenodo.19683825)
- [Zenodo — Filing 2](https://doi.org/10.5281/zenodo.19691251)
- [Zenodo — Filing 3](https://doi.org/10.5281/zenodo.19691374)
- [Zenodo — Filing 4](https://doi.org/10.5281/zenodo.19691449)

© 2026 Duncan Ndungu Ndegwa. All rights reserved.
