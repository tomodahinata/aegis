# @aegiskit/cli

The `aegis` command-line tool — find the security gaps a runtime library can't fix, with an accessible, low-false-positive report.

## Install

```bash
pnpm add -D @aegiskit/cli
```

## Commands

```bash
aegis scan                       # scan and print findings (pretty by default)
aegis scan --format sarif        # SARIF 2.1.0 for GitHub code-scanning
aegis ci --sarif-out aegis.sarif --annotations   # CI: SARIF + GitHub annotations + exit codes
aegis init                       # scaffold a secure() middleware (idempotent)
aegis doctor --url http://localhost:3000   # are the headers ACTUALLY emitted?
aegis diff --base origin/main    # semantic RLS access diff (working tree vs base) — the PR gate
aegis diff --base origin/main --format markdown   # PR-comment-ready body
```

### Options

| Flag | Meaning |
| --- | --- |
| `--format <pretty\|json\|sarif>` | scan output format (`diff` accepts `pretty\|markdown\|json`) |
| `--severity <BLOCKER\|HIGH\|MEDIUM\|LOW\|INFO>` | threshold that fails the run (default `HIGH`) |
| `--strict` | fail on findings of any confidence (default: high-confidence only) |
| `--base <ref>` | (diff) git ref to compare FROM, e.g. `origin/main` — required |
| `--head <ref>` | (diff) git ref to compare TO (default: the working tree) |
| `--trust <fn>` | (diff, repeatable) trusted authorization helper, e.g. `public.is_member` |
| `--no-color` / `--plain` | accessible output (also honors `NO_COLOR`) |
| `--cwd <dir>` | project root |

### Policy diff (`aegis diff`)

Answers the one question a migration PR asks: **did this change widen who can read or write what?**
It reads the authoritative Supabase SQL at a git ref (no checkout) and reports the access delta;
`--format markdown` emits the sticky-comment body the [GitHub Action](../../action.yml) posts. Exits
`1` on high-severity widenings (`--strict` also fails on notice-level attention), so branch protection
on that job turns it into an enforced gate. The read-side helpers are also exported programmatically:

```ts
import { sourcesAtRef, sourcesInWorktree, runDiff } from '@aegiskit/cli';
// sourcesAtRef(cwd, ref) — authoritative SQL at a git ref (via `git show`, no checkout)
// sourcesInWorktree(cwd) — authoritative SQL from the working tree
```

## Trust by design

The #1 way a scanner loses trust is false positives. Aegis defends against that:

- **Confidence gates CI.** Only `high`-confidence findings fail the build by default; `--strict` opts into the rest.
- **Evidence, not names.** Rules resolve AST/import-graph evidence (e.g. *is this `createClient` actually passed the service-role key, in client-reachable code?*) rather than matching identifiers.
- **PASS checks.** Areas you got right are shown green, not nagged.
- **Accessible output.** Every severity carries a text label **and** an ASCII glyph (never color alone); `--plain` is screen-reader friendly.

## Exit codes

`0` clean · `1` findings at/above threshold · `2` usage error · `3` internal error.

## License

MIT
