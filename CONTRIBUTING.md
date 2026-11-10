# Contributing to DevFortress

Thank you for your interest in DevFortress.

## Contribution Model

As of 2026-11-06, DevFortress accepts community contributions under a **Contributor License Agreement (CLA)**, covering both the platform core and the seven SDKs.

## Contributor License Agreement (CLA)

**All contributions require signing our CLA** before your pull request can be merged. The CLA grants DevFortress the right to use your contribution in both the open-source core and the commercial SaaS platform.

### Why a CLA?

- Ensures a clean IP chain for all contributions, including around the
  active patent applications (KIPI KE/P/2026/005970–005973)
- Enables dual-licensing (BUSL-1.1 open-source + commercial SaaS)
- Provides an explicit patent grant — important for security software
- Protects both contributors and the project

### How to Sign

1. Read [CLA.md](./CLA.md)
2. Email support@devfortress.net with your GitHub username to sign
3. Once signed, it applies to all your future contributions — no need to
   sign again unless the CLA is significantly updated

The full CLA text is in [CLA.md](./CLA.md).

## Development Setup

### Prerequisites

- Node.js 20+
- pnpm (recommended)
- Git
- For SDK contributions: the toolchain for that SDK's language (Python 3.9+,
  Go 1.26+, Ruby, PHP 8.2+/Composer, Java 17+/Maven, or .NET 8)

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/devfortress-core.git
cd devfortress-core

# Install dependencies
pnpm install

# Run tests
pnpm test

# Run linting
pnpm lint

# Type-check
pnpm type-check
```

### Branch Naming

- `feat/description` — new features
- `fix/description` — bug fixes
- `docs/description` — documentation
- `test/description` — test additions

## What to Contribute

### Platform core

See [CONTRIBUTING-BACKLOG.md](./CONTRIBUTING-BACKLOG.md) for the current, maintained list of what's open to contribute on the platform core — the single source of truth, so it doesn't drift out of sync with a second list kept here.

### SDK packages (`packages/`)

All eleven SDK/framework-adapter packages are open to contribution:

- `devfortress-sdk` (Node.js)
- `devfortress-python`
- `devfortress-go`
- `devfortress-ruby` / `devfortress-rails` (Rails adapter)
- `devfortress-php` / `devfortress-laravel` (Laravel adapter)
- `devfortress-java` / `devfortress-spring-boot` (Spring Boot adapter)
- `devfortress-dotnet` / `devfortress-aspnetcore` (ASP.NET Core middleware)

Each package's own README documents its test commands and, where relevant, its tag-prefix convention for releases.

## Code Standards

- **Platform:** TypeScript (strict mode), ESLint — run `pnpm lint` before submitting, Jest for tests, no `any` unless absolutely necessary, JSDoc for public APIs
- **SDKs:** follow the existing style and test framework already in use in that package (e.g. `pytest` for Python, `go test` for Go, Minitest for Ruby, PHPUnit for PHP, JUnit for Java, xUnit for .NET)
- **Commits:** Conventional commits (`feat:`, `fix:`, `docs:`, `test:`)

## Pull Request Process

1. Fork the repository and create your branch from `main`
2. Write tests for your changes
3. Ensure the relevant package's tests, lint and type-check all pass
4. Sign the CLA when prompted
5. Submit your pull request with a clear description

## Scope Boundaries

### ✅ In scope for contribution

- Event collection and logging
- View-only dashboards
- API discovery and schema validation
- Input sanitisation and security headers
- Rate limiting
- Basic analytics and metrics
- Self-hosted configuration
- SDK bug fixes, new framework adapters, documentation, and examples across
  all eleven SDK packages listed above

### ❌ Maintainer-only (not open to contribution)

- Automated blocking or session revocation
- AI-powered threat detection, the Platform Intelligence layer, and the
  closed-loop automated response/blocking decision engine
- Compliance reporting, SSO/SAML, SIEM integration
- Any SDK code under a package's own gated/internal path (e.g.
  `tier2_gated/`, `Tier2Gated/`, `tier2gated/`, `internal/tier2/`,
  `agent_identity/`) — these are excluded from this public repo entirely by
  `open-core-strip.sh` and never appear here to contribute to in the first
  place

PRs that add action/response capabilities, or that touch a maintainer-only area, will be redirected to the commercial codebase or declined.

## Reviewer Scope

Security-critical contributions are reviewed against: application, API, and AI-agent credential security. Mobile app security, Web3/smart-contract security, and IoT device security are currently outside the maintainer's expertise. Contributions in those areas are welcome, but should expect longer review, independent second opinions, or may wait for a qualified reviewer to be available.

## What You Can Also Do (no CLA needed)

- **Bug reports:** Open a [GitHub Issue](../../issues) with full steps to reproduce
- **Feature requests:** Open a [GitHub Issue](../../issues) tagged `enhancement`
- **Security disclosures:** Email security@devfortress.net — do NOT open public issues for vulnerabilities

## Questions?

- 📧 Email: support@devfortress.net
- 🐛 Issues: [GitHub Issues](https://github.com/duncan982/devfortress-core/issues)

© 2026 Duncan Ndungu Ndegwa — licensed under Apache-2.0.
