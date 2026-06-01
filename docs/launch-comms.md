# DevFortress — Launch & Communications Playbook

> Internal reference. Covers GitHub launch, marketplace presence, announcement
> channels, and response templates for inbound questions and contributions.
> Last updated: June 2026.

---

## 1. Pre-Launch Checklist (Do Before Setting Repo to Public)

- [ ] Merge `df-open-core-010626-01` → `main` via squash merge on GitHub
- [ ] Set repository visibility to **Public** in GitHub → Settings → Danger Zone
- [ ] Add repository **Topics**: `security`, `api-security`, `nextjs`, `typescript`,
      `supabase`, `open-core`, `threat-detection`, `sdk`, `self-hosted`
- [ ] Set repository **Description**:
      `Application, API and AI Agent Security — Automated. Self-host the open-core platform or use devfortress.net`
- [ ] Set repository **Website**: `https://devfortress.net`
- [ ] Pin the repo on your GitHub profile (GitHub profile → Customize pins)
- [ ] Add `security@devfortress.net` in Cloudflare Email Routing → forward to ndegwa5@gmail.com
- [ ] Add `security@devfortress.net` as Gmail send-as alias (Settings → Accounts → Send mail as → SMTP: smtp.gmail.com)
- [ ] Verify README renders correctly in incognito — click Gumroad, Substack, LinkedIn, X links
- [ ] Create pinned "Welcome & Roadmap" GitHub Issue (see template in Section 4)

---

## 2. GitHub Discovery & Presence

### Repository Setup
The GitHub repository is the primary distribution point for the open-core
platform. Developers discovering DevFortress via GitHub search, npm, or
referrals should land on a repo that immediately communicates what it is,
how to run it, and where to go for the hosted version.

**Topics to add** (drives GitHub search ranking):
`security` `api-security` `nextjs` `typescript` `supabase` `open-core`
`threat-detection` `sdk` `self-hosted` `nodejs` `prisma` `webhook`
`session-management` `ip-blocking` `ai-agent-security`

**Social preview image**: Add a 1280×640px Open Graph image via
GitHub → Settings → Social preview. Use the DevFortress brand mark and
the tagline "Application, API and AI Agent Security — Automated."

### GitHub Marketplace
GitHub Marketplace is for **GitHub Actions** and **GitHub Apps** — not
general SaaS products. DevFortress does not qualify for direct Marketplace
listing at this stage.

**What to do instead:**
- Submit to [awesome-selfhosted](https://github.com/awesome-selfhosted/awesome-selfhosted)
  under the "Security" category once the repo has ≥50 stars
- Submit to [awesome-security](https://github.com/sbilly/awesome-security)
- List on [OSS Alternatives](https://www.opensourcealternative.to/) as an
  alternative to Cloudflare Bot Management and Datadog Application Security

### npm Package Discovery
The `devfortress-sdk` npm package already links to the GitHub repo via
`repository.url` in package.json. Ensure the npm package description and
keywords match the GitHub topics for cross-platform discovery.

---

## 3. Announcement Channels & Sequence

Run announcements in this order over 3–5 days to build momentum:

### Day 1 — Substack (Warm Audience First)
Publish Issue #2 to DevFortress Security Journal.
Subject: `DevFortress is now open-core — here's what that means`

Key points to cover:
- What open-core means for DevFortress (BUSL-1.1, self-host free for
  non-commercial use, hosted platform for production)
- Link to the GitHub repo
- Link to the book (https://devfortress.gumroad.com/l/master-edition)
- What's in the open-core vs what's in the hosted platform
- Call to action: star the repo, try self-hosting, share with your team

### Day 2 — X / Twitter (@DevFortressNet)
Thread format (3–5 tweets):

Tweet 1 (hook):
```
We just open-sourced the core of DevFortress.

Application, API and AI Agent Security — Automated.

Stop attacks before login and inside sessions.
Session revocation, IP blocking, credential isolation — in under 2 seconds.

Self-host free. Production at devfortress.net.

🔗 [GitHub repo link]
```

Tweet 2 (architecture):
```
The architecture is called Token-Aliased Closed-Loop Security.

Your real credentials never leave your infrastructure.
The platform detects threats → webhook → SDK executes → confirmation.

32 inventions. Patent Pending KE/P/2026/005970–005973.

Full technical breakdown in the book 👇
[Gumroad link]
```

Tweet 3 (call to action):
```
If you're building with Next.js, Express, or any Node.js API:

npm install devfortress-sdk

Takes 5 minutes to instrument.
Real-time threat feed shows up in your dashboard immediately.

Star the repo if you find it useful ⭐
[GitHub link]
```

### Day 3 — LinkedIn (Duncan Ndungu Ndegwa personal profile)
Long-form post format:

Opening line (no hashtags, no emojis in first line — LinkedIn algorithm):
```
After months of building, DevFortress is now open-core.
```

Body:
- Personal story: why you built it (the problem you saw with API security)
- What it does in plain language
- What open-core means: free to self-host, production on devfortress.net
- The patent story (32 inventions, KIPI filing)
- The book as the technical companion
- Links: GitHub, devfortress.net, book

Close with a question to drive comments:
```
What's your current approach to API security in production?
```

### Day 4 — Hacker News (Show HN)
Post to Show HN when you have ≥5 GitHub stars (increases credibility).

Title format: `Show HN: DevFortress – Open-core API and AI agent security with automated response`

First comment (post immediately after submission, expands on the title):
```
Hi HN — I've been building DevFortress for the past year.

The core problem: most API security tools detect threats and send you an
alert. You still have to manually respond. DevFortress closes the loop —
detect, decide, execute, confirm — automatically, in under 2 seconds.

The architecture is called Token-Aliased Closed-Loop Security. Your real
credentials never leave your infrastructure. The platform detects a threat,
sends a signed webhook to the SDK running in your app, the SDK executes the
response (revoke session, block IP, isolate credential), and sends
confirmation back.

The open-core layer (what's on GitHub today) handles:
- Event ingestion and surveillance dashboard
- SDK credential management
- Session and IP management UI

The hosted platform adds the ML classifier, Platform Intelligence (B1–B12),
and the blocking decision engine.

Stack: Next.js 15, TypeScript, Supabase, Prisma, Vercel.
License: BUSL-1.1 (free for non-commercial self-hosting).

Happy to answer questions about the architecture or patent approach.
```

### Day 5 — Dev.to / Hashnode
Publish a technical article: `How Token-Aliased Closed-Loop Security works`

Structure:
1. The problem with alert-only security
2. The closed-loop model (detect → decide → execute → confirm)
3. Token aliasing: why real credentials never leave your infra
4. Code walkthrough: instrumenting a Next.js API with devfortress-sdk
5. What's open-core vs hosted
6. Links

Cross-post to both Dev.to and Hashnode with canonical URL pointing to
devfortress.substack.com.

---

## 4. GitHub Issue Templates & Response Templates

### Pinned Welcome Issue
Create this as the first pinned issue immediately after going public:

**Title:** `👋 Welcome to DevFortress — Roadmap & How to Get Help`

**Body:**
```markdown
Welcome to DevFortress open-core.

## What this repository is

This is the open platform layer for DevFortress — the event ingestion API,
surveillance dashboard, credential management, and SDK integration layer.
The hosted platform at devfortress.net adds the ML threat classifier,
Platform Intelligence (B1–B12), and the automated blocking decision engine.

## Roadmap (open-core)

Near-term (next 30 days):
- [ ] /api/threats — full ML-backed threat feed stub → real implementation
- [ ] /api/ml/classify — threat classification endpoint
- [ ] /transparency and /compare pages
- [ ] Improved self-hosting documentation

## How to get help

| Need | Where to go |
|------|-------------|
| Bug in the open-core platform | Open a GitHub Issue |
| Feature request | Open a GitHub Issue tagged `enhancement` |
| Security vulnerability | Email security@devfortress.net — do NOT open a public issue |
| Commercial / enterprise enquiry | Email support@devfortress.net |
| General questions | Start a GitHub Discussion |

## Note on contributions

This repository does not accept pull requests at this time.
See CONTRIBUTING.md for the full explanation and what will change post-MVP.
```

### Response template — Bug report received
```
Thanks for the report. I've reproduced the issue and it's on the radar.

For context on priority: [brief explanation of where it sits in the roadmap].

If you have additional details (Node version, reproduction steps, error logs),
please add them here — it speeds up the fix significantly.
```

### Response template — Feature request received
```
Thanks for the suggestion. This aligns with [existing roadmap item / new idea].

Adding the `enhancement` label. I'll update this issue when it moves to
active development.

If this is blocking a production use case for you, feel free to mention it —
it helps with prioritisation.
```

### Response template — PR opened (contributions not accepted)
```
Thanks for taking the time to open this PR.

As noted in CONTRIBUTING.md, this repository does not accept pull requests
during the current patent application period (KIPI KE/P/2026/005970–005973).
This is a temporary policy that will be revisited post-MVP.

If this addresses a bug, please open a GitHub Issue instead with full
reproduction steps — I'll implement the fix from the core team side.

I appreciate the interest in contributing to DevFortress.
```

### Response template — Security disclosure via GitHub Issue
```
Thank you for the report. I've locked this issue to prevent public
visibility while it's investigated.

Please resend the full details to security@devfortress.net so we can
handle this through the responsible disclosure process. I'll respond
within 48 hours.
```

### Response template — General question / How does X work
```
Good question. [Answer the question directly in 2–4 sentences.]

For deeper context on the architecture, the technical book covers this in
detail: https://devfortress.gumroad.com/l/master-edition

Feel free to follow up here if anything is unclear.
```

---

## 5. Post-Launch Monitoring (First 30 Days)

- **Daily**: Check GitHub Issues and Discussions for new activity
- **Daily**: Monitor @DevFortressNet mentions on X
- **Weekly**: Check npm download stats for devfortress-sdk at npmjs.com/package/devfortress-sdk
- **Weekly**: Check GitHub star count and referrer traffic in GitHub Insights
- **Weekly**: Publish one Substack note (not a full issue — just a short update, architecture insight, or security observation)
- **When ≥50 stars**: Submit to awesome-selfhosted
- **When ≥100 stars**: Write the Hacker News post if not done yet

---

## 6. Key Links Reference

| Resource | URL |
|----------|-----|
| Platform | https://devfortress.net |
| GitHub | https://github.com/duncan982/devfortress-core |
| npm SDK | https://www.npmjs.com/package/devfortress-sdk |
| Book | https://devfortress.gumroad.com/l/master-edition |
| Substack | https://devfortress.substack.com/ |
| LinkedIn | https://www.linkedin.com/in/duncan-ndegwa-564591306/ |
| X / Twitter | https://x.com/DevFortressNet |
| Security email | security@devfortress.net |
| Support email | support@devfortress.net |

---

*© 2026 Duncan Ndungu Ndegwa. Internal document — do not publish.*
