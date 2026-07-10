# Security Policy

Aegis is a defense-in-depth security toolkit. It automates the *horizontal* controls (headers/CSP,
rate limiting, validation, CSRF, secrets hygiene, secure defaults) and *detects and warns* on the
*vertical* risks it cannot fix for you (authorization/IDOR, business logic). It complements secure
design — it does not replace it, and it cannot make any application "completely secure." We hold the
toolkit itself to the same bar it enforces on others, which is what this policy is about. Thank you for
helping keep Aegis and its users safe.

## Supported versions

Aegis is pre-1.0; security fixes land on the **latest published minor** of each `@aegiskit/*` package.
Always upgrade to the latest patch before reporting — the issue may already be fixed. Once a package
reaches 1.0 this policy will gain a defined support window.

| Version            | Supported          |
| ------------------ | ------------------ |
| Latest `0.x` minor | :white_check_mark: |
| Older              | :x:                |

## Reporting a vulnerability

**Please report security issues privately — do not open a public issue, PR, or discussion for them.**

Use GitHub's private vulnerability reporting: on the repository, go to **Security → Advisories → Report a
vulnerability**, or open one directly:

➡️ **<https://github.com/tomodahinata/aegis/security/advisories/new>**

This opens a private advisory visible only to you and the maintainers. Please include, as far as you can:

- the affected package(s) (`@aegiskit/core`, `next`, `scanner`, `dast`, `cli`, `policy-diff`, `mcp`,
  `store-*`, `observability`) and version(s),
- a minimal reproduction — a failing test, a snippet, or a repo,
- the impact you believe it has, and
- any suggested remediation.

### What to expect

This is a small, actively-maintained project; we respond on a best-effort basis and aim to:

- **acknowledge** your report within **3 business days**,
- provide an initial **assessment** (severity, reproducibility) within **10 business days**,
- agree a **coordinated disclosure** timeline with you (typically up to **90 days**, sooner for actively
  exploited issues), publish a GitHub Security Advisory with a CVE where warranted, and
- credit you in the advisory and release notes unless you prefer to remain anonymous.

If you do not get an acknowledgement, please follow up on the advisory thread.

## Scope

In scope — vulnerabilities **in Aegis itself**, for example:

- a way to make a control fail *open* (rate limiter, CSRF/origin check, `defineEnv` boundary, CSP/nonce),
- a scanner/DAST flaw that causes unsafe behavior (e.g. a DAST probe that mutates data or escapes its
  origin/budget confinement), or
- a supply-chain or build-integrity issue in a published `@aegiskit/*` artifact or in this repository's
  own CI/release pipeline.

Out of scope:

- **Findings the scanner reports in _your_ code.** Those are by design — see
  [`docs/coverage.md`](../docs/coverage.md) for what Aegis does and does not detect.
- A **false negative** (Aegis missing a vulnerability class). Aegis never claims to find everything; missed
  coverage is a feature request, not a vulnerability. Please open a normal issue with a fixture.
- The example app (`apps/demo`) and the intentionally vulnerable scanner corpus under
  `packages/scanner/fixtures/`.
- Vulnerabilities only reachable by disabling Aegis's fail-secure defaults, or that require an
  already-misconfigured or already-compromised host.

## Safe harbor

We consider good-faith security research that respects this policy — avoiding privacy violations, data
destruction, and service degradation, and using only your own accounts/test data — to be authorized, and
will not pursue or support legal action against it. If in doubt, ask first in a private advisory.
