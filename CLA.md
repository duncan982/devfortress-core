# DevFortress Contributor License Agreement (CLA)

**Version 2.0 — April 2026**

Thank you for your interest in contributing to DevFortress ("Project"). This Contributor License Agreement ("Agreement") documents the rights granted by contributors to DevFortress.

## Definitions

- **"You"** (or **"Contributor"**): the individual or legal entity making a Contribution
- **"Contribution"**: any original work of authorship, including modifications or additions, submitted to the Project
- **"Project"**: `devfortress-core`, DevFortress's open-core repository (see
  "When This CLA Applies" below for the exact scope within it)
- **"Maintainer"**: Duncan Ndegwa (duncan982) and designated project maintainers

---

## When This CLA Applies

This CLA is **required for all contributions** to `devfortress-core` (Apache-2.0 licensed) — the only repository contributors have access to. That means:

- The specific allowlisted platform-interface files under `app/**` that are
  synced out to `devfortress-core` (not the private repo's `app/` tree as a
  whole — see `.github/open-core-allowlist.txt` in the private repo for the
  exact, curated set)
- The 11 SDK/framework-adapter packages under `packages/` — `devfortress-sdk`,
  `devfortress-python`, `devfortress-go`, `devfortress-ruby`/`devfortress-rails`,
  `devfortress-php`/`devfortress-laravel`, `devfortress-java`/`devfortress-spring-boot`,
  and `devfortress-dotnet`/`devfortress-aspnetcore` — minus each package's own
  gated/internal subpath, which never leaves the private repo in the first
  place

`packages/core/` and `packages/premium/` are **not** part of this — both are private-repo-only directories that are never synced to `devfortress-core` and so are never reachable by a contributor at all.

### Why a CLA for Open-Source Contributions?

The CLA ensures a clean IP chain and enables DevFortress to:

1. **Dual-license** — use contributions in both the Apache-2.0 core and the
   commercial SaaS platform without legal ambiguity
2. **Patent grant** — the Apache-2.0 license + CLA together provide explicit
   patent grants, critical for security software
3. **Relicense if needed** — adapt licensing strategy as the project grows
   without requiring re-consent from every contributor

---

## Grant of Rights

### 1. Copyright License

You hereby grant to the Project Maintainer and to recipients of software distributed by the Project a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to:

- Reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Your Contribution and such derivative works
- Use Your Contribution in commercial products and services
- Modify, enhance, and incorporate Your Contribution into proprietary software

### 2. Patent License

You hereby grant to the Project Maintainer and to recipients of software distributed by the Project a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work, where such license applies only to those patent claims licensable by You that are necessarily infringed by Your Contribution(s) alone or by combination of Your Contribution(s) with the Work to which such Contribution(s) was submitted.

### 3. Right to Grant

You represent that:

- You are legally entitled to grant the above licenses
- If your employer(s) has rights to intellectual property that you create, you have received permission to make Contributions on behalf of that employer, or your employer has waived such rights
- Your Contribution is your original creation and does not violate any third-party rights

---

## Compensation

### Current Stage (Early-Stage)

DevFortress is early-stage. At this stage:

- **No monetary compensation** is guaranteed for Contributions
- Contributors receive recognition via GitHub (commit history, contributor graph) and, on request, a personal reference letter from the maintainer

### Future Compensation

Compensation, if any, is at the Maintainer's sole discretion as the project grows — no specific tiers or percentages are committed to in advance.

**Important**: Future compensation is **not guaranteed** and depends on project success. This CLA does not create an employment or contractor relationship.

---

## Representations

You represent and warrant that:

1. Your Contribution is your original work
2. You have the right to grant the licenses in this Agreement
3. Your Contribution does not contain any viruses, malware, or malicious code
4. Your Contribution does not infringe on any third-party intellectual property rights
5. You have not been compensated by another party for this Contribution

---

## No Obligation

You understand that:

1. The decision to include Your Contribution is at the sole discretion of the Maintainer
2. This Agreement does not obligate the Project to use Your Contribution
3. The Project may modify or remove Your Contribution at any time

---

## Miscellaneous

### Governing Law

This Agreement shall be governed by and construed in accordance with the laws of Kenya, without regard to its conflict of laws provisions.

### Entire Agreement

This Agreement constitutes the entire agreement between You and the Project concerning the subject matter hereof.

### Amendments

The Project may update this CLA. Contributors will be notified of significant changes.

### Severability

If any provision of this Agreement is found to be unenforceable, the remaining provisions will continue in effect.

---

## Signing This CLA

### Electronic Signature

By contributing to any DevFortress repository, you agree to this CLA. You can sign electronically:

1. **Via Email**: Send an email to support@devfortress.net with your GitHub username

### One-Time Signature

Once you sign this CLA, it applies to all your future Contributions to the Project. You don't need to sign again unless the CLA is significantly updated.

---

## Contact

For questions about this CLA:

- **Email**: support@devfortress.net
- **GitHub Discussions**: [Project Discussions](https://github.com/duncan982/devfortress-core/discussions)

---

## Agreement

By submitting a Contribution to any DevFortress repository, you acknowledge that you have read, understood, and agree to be bound by this Contributor License Agreement.

---

**Signature Block (for email submissions):**

```
I, [Your Full Legal Name], hereby agree to the DevFortress Contributor License Agreement (Version 2.0).

GitHub Username: [Your GitHub Username]
Email: [Your Email]
Date: [Date]

Signature: [Your Name or Electronic Signature]
```

---

_This CLA is based on the Apache Individual Contributor License Agreement with modifications for the DevFortress open-core business model._
