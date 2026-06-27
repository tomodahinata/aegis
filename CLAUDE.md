# Aegis — repository protocol

Aegis is a drop-in, **defense-in-depth** security toolkit for Next.js/Supabase SaaS. It productizes battle-tested in-house security patterns into one authoritative, tested package, and ships a scanner for what a library cannot auto-fix.

## Non-negotiable framing

**Never claim Aegis "completely protects" anything.** No tool does, and saying so breeds false confidence — the worst security outcome. Aegis automates the *horizontal* controls (headers/CSP, rate limiting, validation, CSRF, secrets hygiene, secure defaults) and *detects/warns* on the *vertical* risks it cannot fix for you (authz/IDOR, business logic). It complements secure design; it does not replace it. All docs and copy must say exactly this.

## Engineering protocol

- **Read the nearest `CLAUDE.md` first** (this file + any in the package you touch). Nearest wins on conflict.
- **A change without a test is incomplete.** Co-locate `*.test.ts` next to source; use Vitest + `fast-check` for invariants.
- **Prove it works.** Run `pnpm --filter <pkg> typecheck` and `pnpm test` and act on the output before declaring done.
- **Smallest public surface.** Export only what is consumed. Everything else stays module-private.
- **Never read `process.env` outside a typed env boundary** (`@aegiskit/core` `defineEnv`). This is a rule the toolkit enforces on others — we hold ourselves to it.
- **`@aegiskit/core` is runtime-agnostic:** no `node:` imports, no DOM globals. Use Web Crypto via `globalThis.crypto` only. It must run on Node, Edge, and the browser.
- **Fail secure.** On ambiguity or error in a security decision, deny (or omit the insecure header) — never fail open silently.
- **Minimal diffs, Conventional Commits.** `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.

## Layout

`packages/{core,next,store-upstash,scanner,cli}` · `apps/demo` (integration harness) · `fixtures/{vuln,good}` (scanner corpus). Internal cross-package imports resolve to `src` (dev `exports`); published artifacts ship `dist` (tsup, via `publishConfig`).

## Commands

`pnpm verify` (build + typecheck + test + lint) · `pnpm test` · `pnpm typecheck` · `pnpm fix` (Biome write).
