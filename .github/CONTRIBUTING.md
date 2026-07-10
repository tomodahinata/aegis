# Contributing to Aegis

Thank you for your interest. Aegis is a security toolkit, so the bar is high and the process is
deliberately explicit — a change without a test is incomplete, and a security decision that is unsure
must fail secure.

By contributing you agree that your work is licensed under the repository's [MIT License](../LICENSE).
The **"Aegis" and "@aegiskit" names and brand are not covered by that license** — see
[TRADEMARKS.md](../TRADEMARKS.md).

## Ground rules

- **Read the nearest `CLAUDE.md` first** (the repo root one, plus any in the package you touch). It is the
  authoritative engineering protocol; the nearest wins on conflict.
- **Never claim Aegis "completely protects" anything.** It automates horizontal controls and
  detects/warns on the vertical risks it cannot fix. All code and copy must say exactly that.
- **Fail secure.** On ambiguity or error in a security decision, deny — never fail open silently.
- **Smallest public surface.** Export only what is consumed.

## Development setup

```bash
corepack enable          # use the pinned pnpm from package.json "packageManager"
pnpm install             # frozen install; also wires up the git hooks (lefthook)
pnpm verify              # build + typecheck + test + lint — the full local gate
```

Node ≥ 24 and pnpm ≥ 10 are required (`preinstall` blocks non-pnpm installs).

## Making a change

1. **Branch off `main`.** Direct pushes to `main` are blocked by a ruleset — all changes land through a
   pull request whose required checks must pass.
2. **Write the test with the change.** Co-locate `*.test.ts` next to the source; use Vitest, and
   `fast-check` for invariants. The coverage ratchet and the scanner precision gate (precision must stay
   `1.0`, recall must not regress) are enforced in CI.
3. **Add a changeset** for any user-facing change: `pnpm changeset`. Pick the affected packages and a
   semver bump; write the entry for a *consumer* reading the changelog. No changeset = no release.
4. **Conventional Commits** (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`). Enforced
   locally (`commit-msg` hook) and again in CI.
5. **Open the PR.** The local `pre-push` hook runs the same gates CI does, so a green push stays green.
   Fill in the template. CI will run lint/typecheck/build, tests + coverage, the precision gate, CodeQL,
   dependency-audit, gitleaks, and a dogfood self-scan.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Release flow

Releases are automated with Changesets and documented in [RELEASING.md](../RELEASING.md). In short:
merge feature PRs (each with a changeset) → a bot maintains a "Version Packages" PR → merging that PR
publishes to npm with provenance. You never run `npm publish` by hand.
