# Security policy

Aegis is a security toolkit, so we hold its own code to the bar it enforces on others. Thank you for
helping keep it and its users safe.

## Reporting a vulnerability

**Please report security issues privately — do not open a public issue, PR, or discussion for them.**

Use GitHub's private vulnerability reporting: on the repository, go to **Security → Advisories → Report a
vulnerability** (<https://github.com/tomodahinata/aegis/security/advisories/new>). This opens a private
advisory visible only to you and the maintainers.

Please include, as far as you can:

- the affected package (`@aegiskit/core`, `next`, `scanner`, `dast`, `cli`, `store-*`, `observability`) and
  version,
- a minimal reproduction (a failing test, a snippet, or a repo),
- the impact you believe it has, and
- any suggested remediation.

## What to expect

This is a small, actively-maintained project; we respond on a best-effort basis and aim to:

- **acknowledge** your report within **3 business days**,
- provide an initial **assessment** within **10 business days**,
- agree a **coordinated disclosure** timeline with you (typically up to **90 days**, sooner for actively
  exploited issues), and
- credit you in the advisory and release notes unless you prefer to remain anonymous.

If you do not get an acknowledgement, please follow up on the advisory thread.

## Scope

In scope — vulnerabilities **in Aegis itself**, for example:

- a way to make a control fail *open* (rate limiter, CSRF/origin check, `defineEnv` boundary, CSP/nonce),
- a scanner/DAST flaw that causes unsafe behavior (e.g. a DAST probe that mutates data or escapes its
  origin/budget confinement), or
- a supply-chain or build-integrity issue in a published `@aegiskit/*` artifact.

Out of scope:

- **Findings the scanner reports in _your_ code.** Those are by design — see
  [`docs/coverage.md`](docs/coverage.md) for what Aegis does and does not detect.
- A **false negative** (Aegis missing a vulnerability class). Aegis never claims to find everything; missed
  coverage is a feature request, not a vulnerability. Please open a normal issue with a fixture.
- Vulnerabilities only reachable by disabling Aegis's fail-secure defaults.

## Supported versions

Pre-1.0: only the **latest released minor** of each `@aegiskit/*` package receives security fixes. Once a
package reaches 1.0 this policy will be updated with a support window.

## Safe harbor

We consider good-faith security research that respects this policy — avoiding privacy violations, data
destruction, and service degradation, and using only your own accounts/test data — to be authorized, and
will not pursue or support legal action against it. If in doubt, ask first in a private advisory.
