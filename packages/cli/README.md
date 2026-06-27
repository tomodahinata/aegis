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
```

### Options

| Flag | Meaning |
| --- | --- |
| `--format <pretty\|json\|sarif>` | scan output format |
| `--severity <BLOCKER\|HIGH\|MEDIUM\|LOW\|INFO>` | threshold that fails the run (default `HIGH`) |
| `--strict` | fail on findings of any confidence (default: high-confidence only) |
| `--no-color` / `--plain` | accessible output (also honors `NO_COLOR`) |
| `--cwd <dir>` | project root |

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
