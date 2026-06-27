# Scanner benchmark harness

A reproducible precision/recall measurement of the scanner over the labeled fixture corpus
(`fixtures/labels.ts` + the `fixtures/{vuln,good,sql}` directories). It exists so we can make — and keep
honest — a concrete claim about our own detection quality, and so CI fails the moment that quality slips.

The unit of truth is a `(fixture, ruleId)` pair, not a raw finding:

- **TP** — an expected `(vuln-fixture, ruleId)` pair that fired.
- **FN** — an expected pair that did *not* fire → drives **recall**.
- **FP** — any rule firing inside a *good* fixture → drives **precision** (good fixtures must be silent).

A rule that fires in a vuln fixture but is neither expected nor explicitly allowed is recorded as
`unexpected` (informational), not a false positive — a vuln file may legitimately contain a second real
flaw. Precision is therefore anchored to the good corpus, exactly where the trust gate lives.

## The gate

Two complementary guarantees, both enforced by `evaluateGate` (`gate.ts`) and exercised in `gate.test.ts`:

1. **Precision hard floor — must stay 1.0.** Zero false positives is the trust wedge; any FP on a good
   fixture fails the gate, regardless of the baseline.
2. **No regression vs. `baseline.json`.** Overall recall may not drop, no per-rule recall may drop, no
   baseline rule may vanish from the corpus, and neither the vuln nor the good corpus may silently shrink.

## Scripts

Run from the package root (`packages/scanner`), e.g. `pnpm --filter @aegiskit/scanner bench`:

| Script         | What it does                                                                       |
| -------------- | ---------------------------------------------------------------------------------- |
| `bench`        | Prints the plain-ASCII precision/recall table (a CI/dev artifact — no color).       |
| `bench:json`   | Emits the canonical snapshot JSON (sorted keys, no timing, no paths — byte-stable).  |
| `bench:check`  | Runs the regression gate and **exits non-zero** on any precision/recall regression. |
| `bench:update` | Rewrites `baseline.json` from the current corpus — a deliberate, reviewed act.       |

The gate also runs as a unit test under `pnpm test`, so a regression is caught in CI even without
`bench:check`.

## `baseline.json`

The committed, citable snapshot of "we measured our own precision/recall." It stores the gate-relevant
projection of the metrics (overall + macro + per-rule numbers, the false-negative/false-positive lists,
and the corpus sizes — no `unexpected`, no timing, no absolute paths) with sorted keys, so it is a
reproducible artifact and its diffs are reviewable.

To intentionally move the bar (e.g. after adding fixtures or a rule), run `bench:update` and review the
`baseline.json` diff in the PR. Never edit it by hand.
