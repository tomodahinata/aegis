# Security Policy

Aegis is a defense-in-depth security toolkit. It automates the *horizontal* controls (headers/CSP,
rate limiting, validation, CSRF, secrets hygiene, secure defaults) and *detects and warns* on the
*vertical* risks it cannot fix for you (authorization/IDOR, business logic). It complements secure
design — it does not replace it, and it cannot make any application "completely secure." We hold the
toolkit itself to the same bar, which is what this policy is about.

## Supported versions

Aegis is pre-1.0; security fixes land on the latest published minor of each `@aegiskit/*` package.

| Version            | Supported          |
| ------------------ | ------------------ |
| Latest `0.x` minor | :white_check_mark: |
| Older              | :x:                |

Always upgrade to the latest patch before reporting — the issue may already be fixed.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub Security Advisories:

➡️ **<https://github.com/tomodahinata/aegis/security/advisories/new>**
(or the **Security → Report a vulnerability** button on the repository)

Please include, as far as you can:

- the affected package(s) and version(s),
- a description of the issue and its impact,
- a minimal reproduction or proof of concept,
- any suggested remediation.

### What to expect

- **Acknowledgement** within **3 business days**.
- **Initial triage** (severity assessment, whether we can reproduce) within **7 business days**.
- Coordinated disclosure: we agree a timeline with you, ship a fix, publish a GitHub Security Advisory
  with a CVE where warranted, and credit you unless you prefer to remain anonymous.

### Scope

In scope: the published `@aegiskit/*` packages and this repository's own CI/release supply chain.

Out of scope: the example app (`apps/demo`), the intentionally vulnerable scanner corpus under
`packages/scanner/fixtures/`, and findings that require a misconfigured or already-compromised host.

Thank you for helping keep Aegis and its users safe.
