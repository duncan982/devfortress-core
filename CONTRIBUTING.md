# Contributing to DevFortress

Thank you for your interest in DevFortress.

## Contribution Model

DevFortress uses a **one-way open-core model**:

- The private repository is the single source of truth
- This public repository is a downstream snapshot, synced manually by the core team
- Pull requests are **not accepted** at this time

This is intentional and permanent for the foreseeable future. The reasons are:

1. **Active patent applications** — KIPI KE/P/2026/005970–005973 are pending. Accepting third-party code during this window introduces inventorship complexity that could weaken the filings.
2. **Commercial IP boundary** — The open platform layer is licensed under BUSL-1.1. The SDK and Platform Intelligence layer are proprietary. Maintaining a clean boundary requires that all code originates from the core team.
3. **Security product integrity** — Every line of code in a security platform must be fully audited. External PRs introduce review overhead we cannot responsibly commit to pre-launch.

## What You CAN Do

- **Bug reports:** Open a [GitHub Issue](../../issues) with full steps to reproduce
- **Feature requests:** Open a [GitHub Issue](../../issues) tagged `enhancement`
- **Security disclosures:** Email security@devfortress.net — do NOT open public issues for vulnerabilities
- **Fork it:** The BUSL-1.1 license permits non-production use. You are welcome to fork, study, and self-host for internal/non-commercial purposes.

## Post-MVP: Contributions Will Open

After MVP launch we intend to:

1. Introduce a **CLA (Contributor License Agreement)** — all contributors will assign IP rights to Duncan Ndungu Ndegwa before any PR is merged
2. Open a defined set of modules (non-core UI, documentation, SDK examples) for community contribution
3. Document the cherry-pick process by which accepted open-core fixes are backported to the private repo

Watch this repo and [devfortress.net](https://devfortress.net) for updates.

## Why No Two-Way Sync?

Community contributions to the public repo are evaluated and, if accepted, reimplemented by the core team in the private repo — they are never merged directly into the public repo. This keeps the IP chain clean and ensures the private repo is always the authoritative source.

© 2026 Duncan Ndungu Ndegwa. All rights reserved.
