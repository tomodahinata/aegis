# Policy Gate week-0 study — trigger frequency & diff-semantics noise

Go/no-go measurements for the PR-time semantic RLS diff ("Policy Gate"), run BEFORE building the
diff engine, on a seeded random sample of the public Supabase corpus discovered by
[`../rls-precision-study`](../rls-precision-study). Same ethics posture as that study: static,
public-source only; no deployed endpoint contacted; aggregate-only, no repository named.

## Method

`measure.mjs` clones (shallow, sparse — `supabase/{migrations,schemas}` only) a seeded sample
(seed 20260708, mulberry32 shuffle) of `repos.txt`, then replays each repo's migration **sequence**
through the shipped `buildRlsModel` — timestamped migration filenames are the change history, so no
git history is needed. The per-step delta classifier is a documented MEASUREMENT PROXY (simpler than
the product diff engine: no permissive/restrictive matrix; fail-safe `unknown`/`function-delegated`
⇒ review). `data/` is gitignored; this README records the aggregates.

## Results (2026-07-08, N=300 sampled, 298 ok)

**(a) Trigger frequency — GO.** Of 153 repos with a timestamped multi-migration history, **93%
merge ≥ 1 access-relevant migration per month** (median 4.78/month; 58% of all 8,714 migrations
replayed touch policies/RLS/grants). The PR-time wedge fires weekly for active repos, not yearly.

**(b) Diff-semantics noise — acceptable, allowlist is load-bearing.** Over 5,049 access-relevant
migrations: **WIDENING 42% / NEUTRAL 31% / REQUIRES_REVIEW 26% / NARROWING 1%**. The 26% review
rate is the price of fail-safe semantics; a `trust function` allowlist must ship in the engine
(not as later polish) to keep mature codebases quiet.

**(c) Function-delegated prevalence.** 24.7% of 22,798 policies delegate to a custom function, and
**57% of RLS-shipping repos have ≥ 1 such policy** — confirming (b): unverifiable helpers are the
dominant review driver.

**(d) Fail-open hole sizing — the pre-launch fixes are mandatory.** Of 298 repos: **40% have
policies on `storage.objects`** (invisible to the current public-schema-only model), **10% contain
`DISABLE ROW LEVEL SECURITY`** (unparsed today → a false-NEUTRAL diff), **31% contain `REVOKE`**
(grants are append-only today). Each hole is common enough that shipping the diff without closing
them would false-NEUTRAL real access changes.

## Decision

**GO**, with two design consequences enforced by these numbers: (1) the `model.ts` fail-open
closures (DISABLE RLS, REVOKE final-state, ALTER POLICY RENAME, storage-schema policies, fail-closed
`uninterpreted` records) are launch-blocking, not hardening; (2) the trusted-helper allowlist is an
engine-level option from day one.

## Reproduce

```bash
pnpm --filter @aegiskit/scanner build
node research/policy-gate-study/measure.mjs 300   # -> data/rows.jsonl
```
