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

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
| ----------- | ------- | ----- |
| Node.js | 20 LTS+ | [nodejs.org](https://nodejs.org) |
| npm | 10+ | Bundled with Node.js 20 |
| pnpm | 9+ | `npm install -g pnpm` |
| Docker Desktop | Latest | Required for local Supabase |
| Supabase CLI | Latest | `npm install -g supabase` |
| devfortress-sdk | Latest | `npm install devfortress-sdk` |

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
pnpm dev
# Open http://localhost:3001
```

> **Note:** Run `npx prisma migrate deploy` after `supabase start` to apply the schema. All variables are documented inline in `.env.example`.

### Environment Variables

Copy `.env.example` to `.env.local` and fill in your Supabase credentials from `supabase start` output:

| Variable | Description | Where to get it |
| -------- | ----------- | --------------- |
| `DATABASE_URL` | PostgreSQL connection string (pooled, port 6543) | `supabase start` output → DB URL |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL | `supabase start` output → API URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon key | `supabase start` output → anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | `supabase start` output → service_role key |
| `DEVFORTRESS_API_KEY` | Your DevFortress API key | [devfortress.net/dashboard](https://devfortress.net/dashboard) |
| `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key | [dash.cloudflare.com](https://dash.cloudflare.com) → Turnstile |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile secret key | Same as above |

The `.env.example` contains Cloudflare Turnstile test keys that pass all checks — safe for local development without a Cloudflare account.

### Available scripts

| Command | Description |
| ------- | ----------- |
| `pnpm dev` | Start development server (port 3001) |
| `pnpm build` | Production build |
| `pnpm start` | Start production server |
| `pnpm lint` | Run ESLint |
| `npx prisma generate` | Regenerate Prisma client after schema changes |
| `npx prisma migrate deploy` | Apply pending migrations |
| `npx prisma studio` | Open Prisma database browser |

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

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

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

## About the Author

DevFortress is designed and built by **Duncan Ndungu Ndegwa**, a software
engineer and security researcher based in Nairobi, Kenya.

The architecture behind this platform — Token-Aliased Closed-Loop Security,
the Platform Intelligence layer, and the agentic detection models — is
documented in depth in:

**[Book title and link — TO BE FILLED BY HUMAN before merge]**
A technical deep-dive into the threat models, design decisions, and
implementation patterns that underpin DevFortress. Written for engineers
who want to understand not just how to use the platform, but why it is
built the way it is.

**[Substack newsletter — TO BE FILLED BY HUMAN before merge]**
Engineering notes, security research, and DevFortress development updates.
Subscribe for architecture breakdowns and early access announcements.

These are shared here as context for the open-core — not as a requirement
to use the platform. The README and docs contain everything needed to run
DevFortress independently.

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
