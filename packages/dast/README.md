# @aegiskit/dast

**Dynamic application security testing for Aegis** — send safe, bounded, **non-destructive** HTTP probes to a **running app you own**, confirm a subset of vulnerabilities at runtime, and **correlate** them with `@aegiskit/scanner`'s static findings.

```bash
# Probe a running localhost app (passive, non-destructive — the safe default).
aegis probe http://localhost:3000

# Confirm static findings at runtime: a "possible SQLi" that reproduces becomes build-blocking.
aegis probe http://localhost:3000 --correlate

# See exactly what it WOULD send, without sending anything.
aegis probe http://localhost:3000 --dry-run

# Enable active (state-changing-method) probes.
aegis probe http://localhost:3000 --active
```

> The credentialed `dast/auth-required` and `dast/idor` probes need test identities, which are
> supplied only via the programmatic API (`probe({ origin, mode: 'active', identities })`). The
> `aegis probe` CLI does not yet expose an `--identities` flag, so `--active` alone enables the
> active-method probes but not the credentialed ones.

## What it does

Static analysis *suspects*; dynamic analysis *confirms*. When the scanner flags a possible SQL injection on `app/api/x/route.ts` and a probe **reproduces** it on the live `/api/x`, Aegis upgrades that finding to **confirmed exploitable at runtime** — raising its confidence to `high` (so it now fails the build) and attaching the real HTTP exchange as evidence. That cross-check is the point: it kills the false-positive fatigue that erodes trust in security tooling.

Findings flow through the **same** reporters as the scanner (`pretty`, `json`, SARIF) — a DAST finding is just a `Finding` located by `METHOD /path` instead of `file:line`.

### Probes

| Probe | Detects | Default |
| --- | --- | --- |
| `dast/security-headers` | CSP/HSTS/X-Frame-Options/etc. missing at runtime | ✓ |
| `dast/cookie-flags` | session cookie without HttpOnly/Secure/SameSite | ✓ |
| `dast/error-disclosure` | leaked stack traces / framework errors | ✓ |
| `dast/open-redirect` | redirect to an attacker-controlled host | ✓ |
| `dast/reflected-xss` | a marker reflected **unescaped** into HTML | ✓ |
| `dast/sql-injection` | boolean-differential / error-based injection (no destruction) | ✓ |
| `dast/ssrf` | server-side fetch of an attacker URL, via an out-of-band **canary** | ✓ |
| `dast/missing-rate-limit` | no 429 across a bounded burst | ✓ |
| `dast/auth-required` | a route marked protected reachable **unauthenticated** | `--active` + identities (API) |
| `dast/idor` | one identity reading another's object | `--active` + identities (API) |

## Safety (non-negotiable)

This is a **defensive tool you point at your own app**, not an attack framework. It is built to be impossible to casually misuse:

- **Localhost by default.** A non-loopback target requires **both** `--allow-remote` and `--i-own "<attestation>"` whose origin matches the target. The attestation is recorded in the report.
- **Scope-confined.** Requests never leave the target origin; off-origin redirects and link-local / cloud-metadata IPs (`169.254.169.254`) are hard-blocked even with consent (the SSRF-into-the-scanner defense). Redirects are captured, never followed.
- **Non-destructive.** SQLi uses boolean/error *inference* (never `DROP`/stacked queries); SSRF uses an out-of-band canary (never a real internal fetch); rate-limit uses a small bounded burst. Nothing mutates state.
- **Bounded.** A hard request cap, concurrency limit, self-rate-limit, per-request timeout, and global deadline — enforced centrally so no probe can exceed them.
- **Fail secure.** On any ambiguity it sends nothing; a probe that errors is *inconclusive*, never a pass. Response bodies are truncated and secrets redacted before they enter a report.

## Honest scope

DAST covers **only the surface it can reach and was told to probe**. It is **not exhaustive**, does not crawl your whole app, and finds nothing in code paths it never reaches. Aegis does **not** "run every attack a world-class attacker would" — that claim is false, and false confidence is itself the worst security outcome. This **complements** — it does not replace — static analysis, the runtime controls in `@aegiskit/next`/`@aegiskit/core`, code review, and **manual penetration testing**. Only point it at systems you own or are explicitly authorized to test.

## License

MIT
