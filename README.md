# DevFortress — Open-Core Security Platform

![Patent Pending](https://img.shields.io/badge/Patent-Pending-blue)
![License](https://img.shields.io/badge/License-BUSL--1.1-green)
![npm](https://img.shields.io/npm/v/devfortress-sdk)

**DevFortress** is an open-core security platform for APIs, applications,
and AI agents. It implements the **Credential Isolation Closed-Loop Security**
architecture — real-time threat classification and automated response via
HMAC-signed webhook callbacks, with real credentials never leaving your
infrastructure.

## SDK — source and packages

As of 2026-11-06, SDK source for all supported languages lives in this
repository under `packages/`, and contributions are welcome under our
[CLA](./CLA.md) — see [CONTRIBUTING.md](./CONTRIBUTING.md). Each package's
registry:

| Language            | Package                                   | Registry        | Status      |
| ------------------- | ----------------------------------------- | --------------- | ----------- |
| Node.js             | `devfortress-sdk`                         | npm             | Live        |
| Python              | `devfortress-sdk`                         | PyPI            | Coming soon |
| Go                  | `devfortress-go`                          | Go module proxy | Coming soon |
| Ruby                | `devfortress-sdk`                         | RubyGems        | Coming soon |
| Ruby (Rails)        | `devfortress-sdk-rails`                   | RubyGems        | Coming soon |
| PHP                 | `devfortress/devfortress-sdk`             | Packagist       | Coming soon |
| PHP (Laravel)       | `devfortress/sdk-laravel`                 | Packagist       | Coming soon |
| Java                | `net.devfortress:devfortress-sdk`         | Maven Central   | Coming soon |
| Java (Spring Boot)  | `net.devfortress:devfortress-spring-boot` | Maven Central   | Coming soon |
| .NET                | `DevFortress.Sdk`                         | NuGet           | Coming soon |
| .NET (ASP.NET Core) | `DevFortress.AspNetCore`                  | NuGet           | Coming soon |

### Node.js

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
    credential_isolation: true,
  },
});

export async function middleware(request: NextRequest) {
  await df.observe(request);
  return NextResponse.next();
}
```

Full documentation: [devfortress.net/docs](https://devfortress.net/docs)

## Getting Started

### Prerequisites

| Requirement     | Version | Notes                            |
| --------------- | ------- | -------------------------------- |
| Node.js         | 20 LTS+ | [nodejs.org](https://nodejs.org) |
| npm             | 10+     | Bundled with Node.js 20          |
| pnpm            | 9+      | `npm install -g pnpm`            |
| Docker Desktop  | Latest  | Required for local Supabase      |
| Supabase CLI    | Latest  | `npm install -g supabase`        |
| devfortress-sdk | Latest  | `npm install devfortress-sdk`    |

### Quick Start (≤10 commands)

```bash
git clone https://github.com/duncan982/devfortress-core.git
cd devfortress-core
cp .env.example .env.local
# Edit .env.local — fill in your Supabase credentials (see Environment Variables below)
pnpm install
supabase start
# Copy the API URL, anon key, and service_role key printed above into .env.local
npx prisma migrate deploy
pnpm dev  # or: npm run dev
# Open http://localhost:3001
```

> **Note:** Run `npx prisma migrate deploy` after `supabase start` to apply the schema. All variables are documented inline in `.env.example`.

### Environment Variables

Copy `.env.example` to `.env.local` and fill in your Supabase credentials from `supabase start` output:

| Variable                         | Description                                      | Where to get it                                                |
| -------------------------------- | ------------------------------------------------ | -------------------------------------------------------------- |
| `DATABASE_URL`                   | PostgreSQL connection string (pooled, port 6543) | `supabase start` output → DB URL                               |
| `NEXT_PUBLIC_SUPABASE_URL`       | Supabase project URL                             | `supabase start` output → API URL                              |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY`  | Supabase anon key                                | `supabase start` output → anon key                             |
| `SUPABASE_SERVICE_ROLE_KEY`      | Supabase service role key                        | `supabase start` output → service_role key                     |
| `DEVFORTRESS_API_KEY`            | Your DevFortress API key                         | [devfortress.net/dashboard](https://devfortress.net/dashboard) |
| `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key                    | [dash.cloudflare.com](https://dash.cloudflare.com) → Turnstile |
| `TURNSTILE_SECRET_KEY`           | Cloudflare Turnstile secret key                  | Same as above                                                  |

The `.env.example` contains Cloudflare Turnstile test keys that pass all checks — safe for local development without a Cloudflare account.

### Available scripts

| Command                     | Description                                   |
| --------------------------- | --------------------------------------------- |
| `pnpm dev` / `npm run dev`  | Start development server on port 3001         |
| `pnpm build`                | Production build                              |
| `pnpm start`                | Start production server                       |
| `pnpm lint`                 | Run ESLint                                    |
| `npx prisma generate`       | Regenerate Prisma client after schema changes |
| `npx prisma migrate deploy` | Apply pending migrations                      |
| `npx prisma studio`         | Open Prisma database browser                  |

## What's in this repository

This repository contains the **open platform layer** — the interfaces,
schemas, and UI the SDKs communicate with — plus the SDK source itself.

| Path                       | Description                                                                |
| -------------------------- | -------------------------------------------------------------------------- |
| `app/api/events/ingest/`   | Event ingestion interface                                                  |
| `app/api/sdk/credentials/` | SDK credential management interface                                        |
| `app/collect/`             | Collect phase UI                                                           |
| `prisma/migrations/`       | Database schema — PostgreSQL migrations                                    |
| `packages/`                | SDK source for all 11 supported languages/frameworks — see the table above |

The hosted platform — the LEARN phase, the Platform Intelligence layer, threat
classifiers, and the blocking decision engine — is proprietary and available
via [devfortress.net](https://devfortress.net). Each SDK package's own
gated/internal path (`tier2_gated/`, `Tier2Gated/`, `tier2gated/`,
`internal/tier2/`, `agent_identity/`) is excluded from this repository for
the same reason and never appears here.

## SDK Specialization Modes

| Mode                       | Description                             | Availability |
| -------------------------- | --------------------------------------- | ------------ |
| `app_security`             | Baseline API and application protection | All tiers    |
| `credential_isolation`     | REDACTED — credential aliasing and rotation  | Pro+         |
| `account_takeover_defense` | A5, A6, A11–A15 bundle                  | Pro+         |
| `commerce_abuse_defense`   | A14 + anti-fraud controls               | Pro+         |
| `ai_agent_security`        | A7, A10, A16, A17 — agentic detection   | Pro+         |
| `llm_protection`           | Prompt injection and output security    | Enterprise   |
| `mcp_protection`           | MCP protocol security and audit         | Enterprise   |
| `fintech_security`         | PCI-DSS, transaction monitoring         | Enterprise   |
| `healthcare_security`      | HIPAA, PHI detection                    | Enterprise   |
| `web3_protection`          | Wallet and smart contract protection    | Enterprise   |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

As of 2026-11-06, this repository accepts pull requests under a
[Contributor License Agreement (CLA)](./CLA.md), covering both the platform
layer and the SDK packages under `packages/`.

You are also welcome to:

- Open a **GitHub Issue** to report a bug or request a feature
- Email security@devfortress.net for responsible vulnerability disclosure —
  do not open public issues for security vulnerabilities
- Star and watch the repo for updates

## About the Author

DevFortress is designed and built by **Duncan Ndungu Ndegwa**, a software
engineer and security researcher based in Nairobi, Kenya.

The architecture behind this platform — Credential Isolation Closed-Loop Security,
the Platform Intelligence layer, and the agentic detection models — is
documented in depth in:

**[Credential Isolation Closed-Loop Security](https://devfortress.gumroad.com/l/master-edition)** — A technical deep-dive into the threat models, design decisions, and implementation patterns that underpin DevFortress. Written for engineers who want to understand not just how to use the platform, but why it is built the way it is.

Follow updates, architecture deep-dives, and security research from the core team: **[DevFortress Security Journal](https://devfortress.substack.com/)**

These are shared here as context for the open-core — not as a requirement
to use the platform. The README and docs contain everything needed to run
DevFortress independently.

## License

Open platform layer: [BUSL-1.1](https://mariadb.com/bsl11/)
SDK and platform intelligence layer: Proprietary — All rights reserved

## Patent Notice

Credential Isolation Security, Closed-Loop Automated Response, and Platform
Intelligence are Patent Pending — KIPI KE/P/2026/005970–005973.

© 2026 Duncan Ndungu Ndegwa. All rights reserved.
