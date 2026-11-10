# Community Contribution Backlog

A set of concrete, scoped items from our internal backlog that don't require any context beyond what's already in this repository. Good starting points if you want to contribute but aren't sure where to begin. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the general contribution guidelines and CLA requirement before opening a PR.

These are suggestions, not commitments — open an issue first if you'd like to claim one, so two people don't end up duplicating work.

## Good first issues

- **SDK Quick Start in the README.** The Node.js SDK's README could use a
  clearer, copy-pasteable Quick Start section so a new integrator can get a
  working call wired up without reading the full API reference first.


## Feature-parity audit across SDK ports

DevFortress ships SDK ports for Python, PHP, Ruby, Java, Go, and .NET alongside the original Node.js SDK. The Node.js SDK itself is equally open to contribution — bug fixes, docs, and parity fixes all welcome — it's just the reference implementation the other six get audited against here. A contributor-friendly task that doesn't require deep context: pick one non-Node port and audit it against the Node.js SDK's public surface (method names, parameter shapes, test coverage) and file an issue for anything missing or inconsistent. This is useful even as a partial pass — a gap list for one language is a complete, mergeable contribution on its own.

## Optional SDK instrumentation

- **Lightweight call-timing wrapper.** Since the SDK already sits in the
  request path, an opt-in wrapper that records start/end timestamps and
  duration per instrumented function call would let integrators get basic
  performance visibility without adding a separate APM dependency. This is
  a standalone, additive feature — it doesn't touch any existing security
  path.

## SDK packaging hardening

- **Java JPMS modularization.** Java's package-private visibility is scoped
  to the package _name_, not a compiled artifact — a second, independent
  JAR declaring classes under the same internal package name can reach
  across the boundary purely via classpath placement. Migrating
  `packages/devfortress-java` to a real JPMS module (`module-info.java`,
  exporting only the public package) would close this specific gap at the
  module-system level, regardless of classpath tricks. A nontrivial
  Maven/packaging change, not a quick wire-up — good for a contributor
  comfortable with Java's module system.

## Demos and docs

- **Before/after SDK comparison demo.** An interactive, side-by-side demo
  showing how a request is handled with and without the SDK installed would
  help prospective users understand what actually changes at the request
  level. A static or lightly-interactive version is enough to start.

## Exploratory (needs scoping before implementation)

- **Mobile SDK bindings.** There's interest in a Kotlin/Swift pair or a
  React Native/Flutter wrapper, but this hasn't been scoped yet — it depends
  on how the existing web-focused multi-language SDK work settles first. If
  you're interested in this, open an issue to discuss scope before writing
  code; we'd rather align on the shape of the API first.

- **Migration baseline for self-hosters.** `prisma migrate deploy` against
  an empty Postgres database fails partway through the migration history —
  some early tables were created outside the migration files themselves, and
  one migration depends on Supabase's `auth` schema, which a plain Postgres
  doesn't have. A new self-hoster or CI job can't build the schema from the
  migration files alone today. Needs a scoping decision (a baseline-squash
  migration vs. documenting a schema-first setup) before any implementation
  — open an issue to discuss which direction fits best.

## Exploratory — domain expertise needed

These need a contributor with the specific domain background to scope them first, same treatment as the mobile-bindings entry above — not ready to pick up as-is.

- **Web3/smart-contract security.** If you have a security background in
  this space and see a gap worth closing in the open-core surface, open an
  issue describing it before writing code.
- **IoT device security.** Same — if you have relevant domain expertise and
  see something worth scoping, start with an issue, not a PR.

---

Borderline items we chose to leave out of this list rather than include them: anything that would require explaining our closed-loop response architecture, consent/trust internals, or patent-pending mechanisms to make sense of — those aren't excluded because they're unwelcome, just because they need context this repository doesn't carry on its own. If you've found something in the open-core code that looks like a bug and you're not sure whether it's safe to discuss publicly, email security@devfortress.net first.
