# 🛡️ Aegis

[![CI](https://github.com/tomodahinata/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/tomodahinata/aegis/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tomodahinata/aegis/actions/workflows/codeql.yml/badge.svg)](https://github.com/tomodahinata/aegis/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tomodahinata/aegis/badge)](https://scorecard.dev/viewer/?uri=github.com/tomodahinata/aegis)
[![npm](https://img.shields.io/npm/v/@aegiskit/cli?color=cb3837&logo=npm)](https://www.npmjs.com/package/@aegiskit/cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

**A drop-in, defense-in-depth security toolkit for Next.js / Supabase SaaS.**

Built for developers shipping fast — including with AI coding agents — who don't want to become security experts to be reasonably safe. Add one middleware file and one env module and you get the security controls vibe-coded apps almost always miss.

> **Honest scope.** No tool "completely protects" a web service, and any product that claims to is dangerous — it makes you stop paying attention. Aegis **automates the common, high-impact controls** (security headers/CSP, rate limiting, input validation, CSRF, secrets hygiene, secure defaults) and **scans for the risks it can't auto-fix** (broken authorization/IDOR, business-logic flaws). It dramatically reduces real risk and **complements** secure design — it does not replace it. It composes with your platform's network-layer WAF/bot protection; Aegis is the *application* layer. See the **[coverage matrix](docs/coverage.md)** for the exact rules, their analysis method, and what Aegis deliberately does *not* detect.

## Quick start

**Scan your project — no install, no config:**

```bash
npx @aegiskit/cli scan
```

**Add it to CI** — fail the build on high-confidence findings and upload a SARIF report to GitHub code scanning:

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  aegis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload SARIF to the Security tab
    steps:
      - uses: actions/checkout@v4
      - uses: tomodahinata/aegis@v1 # the Aegis Security Scan action (wraps `aegis ci`)
        with:
          severity: HIGH
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aegis.sarif
```

**Harden the runtime** — add the controls a library *can* own (headers/CSP, rate limiting, CSRF, a typed env boundary):

```bash
npx @aegiskit/cli init
```

## Find → fix

```bash
aegis scan            # find the issues
aegis fix             # preview safe auto-fixes + a guided plan for the rest
aegis fix --write     # apply the auto-fixes (review with `git diff`)
aegis fix --format json   # the same plan, machine-readable — hand it to your coding agent
```

`aegis fix` only auto-applies transforms it can prove safe (e.g. wrapping a route handler with `secureRoute`); anything needing human judgement is reported as precise, copy-pasteable steps. It never claims to fix what it cannot.

## Dataflow (taint) analysis

Beyond syntactic checks, the scanner performs **intraprocedural taint tracking**: within a function it follows untrusted input — request bodies, query params, route `params`, cookies, headers, `useSearchParams()`, `location` — from where it enters to where it is used, and flags it when it reaches a dangerous **sink** without passing through an adequate **sanitizer** for that sink. This surfaces the injection class a pattern-matcher structurally cannot see: **SQL injection** (Supabase `rpc`/raw queries), **SSRF**, **path traversal**, **command injection**, **open redirect**, **DOM-based XSS**, and **code injection** — plus low-noise checks for **weak randomness/hashing**, **non-constant-time secret comparison**, and a heuristic **missing-authorization** review prompt.

Sanitizer adequacy is **sink-specific** and modelled as such: `encodeURIComponent` makes a value safe for a URL but **not** for SQL; `Number()` makes it safe everywhere; a bare `String()` cast makes it safe nowhere. Aegis won't call input safe just because *some* function touched it. Every finding ships the **exact source → sink path** — as an accessible numbered trace in the terminal and as SARIF `codeFlows` (a clickable dataflow in GitHub code-scanning) — so you fix the real flow, not a bare line number.

> **Honest scope — read this.** This analysis is **intraprocedural**: it reasons *within* a function, not across your whole call graph, so it will miss flows that span modules, indirection, or framework-mediated data paths. It is **not** "finding vulnerabilities no human can find" — no static tool can, and believing one does is the fastest way to stop reviewing your own code. It surfaces the high-frequency injection mistakes that AI-assisted Next.js/Supabase code reliably gets wrong, and it **complements** parameterized queries, code review, and threat modeling — it does not replace them. Treat a clean run as "the common injection traps are clear," never "this code is safe." For the vertical risks a library cannot fix — broken authorization/IDOR, business logic — Aegis still only **detects and warns**; closing them is yours. As always, only high-confidence findings fail CI by default, so the dataflow engine adds teeth without adding noise.

## Dynamic analysis — confirm it at runtime

Static analysis *suspects*; dynamic analysis *confirms*. `aegis probe` sends **safe, bounded, non-destructive** HTTP requests to a **running app you own**, confirms a subset of vulnerabilities at runtime (reflected XSS, open redirect, SQL injection, SSRF via an out-of-band canary, missing headers/rate-limit, and — when you supply test identities via the programmatic `@aegiskit/dast` API — missing-auth and IDOR), and **correlates** them with the static scan: a "possible SQLi" that *reproduces* on the live route becomes **confirmed exploitable at runtime**, upgraded to build-blocking with the real HTTP exchange as proof.

```bash
aegis probe http://localhost:3000 --correlate   # static scan + runtime confirmation
aegis probe http://localhost:3000 --dry-run      # show the plan; send nothing
```

> **Safety & honest scope.** This is a defensive tool for an app **you own** — localhost by default; a remote host needs `--allow-remote` + an ownership attestation. It is non-destructive (boolean/error inference for SQLi, an OOB canary for SSRF, bounded bursts for rate-limit), scope-confined (off-origin and cloud-metadata IPs hard-blocked), and bounded by a hard request budget. It covers only the surface it can reach and was told to probe — it is **not** exhaustive and does **not** "run every attack a hacker would." It complements — never replaces — static analysis, code review, and **manual penetration testing**. See [`packages/dast`](./packages/dast).

## RLS verification — the database authorization boundary

For a Supabase app the real authorization boundary is **Postgres Row Level Security**, written in SQL — which a TypeScript scanner is structurally blind to. Aegis now reads your `supabase/migrations/**.sql` and verifies the access-control design where it actually lives: tables shipped **without RLS**, `SECURITY DEFINER` functions that **don't pin `search_path`** (a privilege-escalation vector), write policies **missing `WITH CHECK`**, **unconditional `true`** write predicates, and tables **granted to `anon`**. It then **correlates SQL with code**: a weak-RLS table that your app queries through a non-admin client becomes a **confirmed exposure**, located at the exact query site — the static analog of runtime confirmation.

Every rule is designed to produce **zero findings on a correct, production-grade RLS design** (validated against a real exemplary schema), so a finding means a real gap, not noise.

> **Verify, not replace.** This *verifies* the RLS you wrote and surfaces gaps with precision — it does **not** replace RLS design, code review, or manual penetration testing, and it cannot prove your policies correct (it reasons about their *shape*, not your data model or business rules). A clean run means "the common RLS mistakes are absent," never "your authorization is correct." It complements human review; it does not substitute for it.

## Packages

| Package | What it does |
| --- | --- |
| `@aegiskit/core` | Framework-agnostic, edge-safe primitives: CSP builder, security headers, rate limiter, CSRF/origin, typed env, security events, and the `createHttpSink` event shipper. |
| `@aegiskit/next` | Next.js (App Router) adapters: `secure()` middleware, `secureRoute()` handler wrapper, `getNonce()`, `defineServerEnv`, `createCspReportHandler`. |
| `@aegiskit/store-upstash` | Atomic, serverless-correct rate-limit store backed by Upstash Redis. |
| `@aegiskit/observability` | Read side: pluggable `EventStore`, deterministic posture score, ingestion signature verifier. |
| `@aegiskit/store-supabase` | Persistent `EventStore` on Supabase/Postgres, with a migration (RLS on by default). |
| `@aegiskit/scanner` | Static analysis engine: syntactic checks, **intraprocedural taint/dataflow** for the injection class, and **Supabase RLS/SQL verification** with SQL↔code correlation; source→sink traces; inline suppression + baseline. |
| `@aegiskit/dast` | Dynamic testing: safe, bounded, non-destructive runtime probes against your own app, with SAST↔DAST correlation (confirmed-exploitable). Localhost-default, fail-secure. |
| `@aegiskit/cli` | `aegis scan · fix · init · doctor · ci · probe` — accessible reports, safe auto-fixes, SARIF, CI integration, runtime probing. |
| `@aegiskit/eslint-config` | Edit-time security lint preset (no false positives). |

Plus `apps/dashboard` — a self-hostable, WCAG 2.2 AA security dashboard (posture, events, CSP) that dogfoods Aegis — and a reusable GitHub Action ([`action.yml`](./action.yml)) wrapping `aegis ci`.

## Status

Six phases shipped: the runtime toolkit + scanner/CLI; the observability loop, dashboard, scanner usability, and adoption tooling; remediation (`aegis fix` — safe auto-fixes + a coding-agent handoff); dataflow/taint analysis for the injection class with source→sink traces; dynamic analysis (`aegis probe` — safe runtime confirmation with SAST↔DAST correlation); and Supabase RLS/SQL verification with SQL↔code correlation. See [`CLAUDE.md`](./CLAUDE.md) for the engineering protocol.

## License

MIT
