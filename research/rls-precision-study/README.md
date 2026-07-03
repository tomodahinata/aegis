# Supabase RLS precision study

A reproducible field study that measured — and then hardened — the precision of Aegis's flagship rule
`rls/policy-not-owner-scoped` against **real production code**, not curated fixtures. It is the evidence
behind the claim that Aegis's zero-false-positive design holds on the shapes real Supabase apps ship.

> **Why this exists.** A curated benchmark reporting `precision 1.0` does **not** guarantee real-world
> precision. This study scanned a large public corpus, audited every finding, and drove the rule from a
> false-positive-laden raw rate to a verified-genuine one — distilling each false-positive class into a
> permanent regression fixture so the gain can never silently regress.

## Headline (2026-06-28)

**Population (funnel).** GitHub code search surfaced **2,230** unique public repositories with a
`CREATE POLICY` under `supabase/migrations` or `supabase/schemas`; we scanned **450** of them. **445**
ship RLS (≥ 1 `CREATE POLICY`), and **~52,800** RLS policies were analyzed in total. Static analysis of
the migration SQL only — no deployed app was ever contacted (see ethics below).

| | Flag rate (repos with RLS) | Findings (policies) | What the iteration fixed |
|---|---:|---:|---|
| raw (pre-hardening) | 19.3% | 573 | — (a full audit found **~83% were false positives**) |
| after hardening | **8.1%** (36 / 445) | **99** | **0 residual false positives** — every finding ground-truthed as a genuine authenticated-only gap |

So the hardened headline: **36 of the 445 RLS-shipping repos (8.1%)** have ≥ 1 policy that authenticates
but does not scope rows to the owner — **99 such policies, ≈ 0.19% of all ~52,800 RLS policies analyzed**.

> **Reproducible artifact.** Every figure above is exactly what [`aggregate.py`](./aggregate.py) emits from
> a run (into the gitignored `data/summary.md`); they are recorded here so any number cited in the public
> write-up traces to a committed source. Re-running the scripts repopulates a fresh corpus — because the
> GitHub code-search population drifts over time, the rates will move slightly; this README pins the
> 2026-06-28 run that the write-up cites. Raw clones and per-repo results stay `.gitignore`d (ethics +
> size); the rates are aggregate and name no repository.

## Replication at scale (2026-07-01)

The original 450-repo run was **replicated at 2× scale on an independent seeded sample**, and the headline
held. GitHub code search surfaced **2,234** unique public repos; we scanned **1,000** (independent seed,
not the 2026-06-28 set). **998** scanned cleanly, **994** ship RLS, and **116,662** RLS policies were
analyzed — ~2.2× the original policy volume.

| Rule | Flag rate | Findings (policies) | Manual triage |
|---|---:|---:|---|
| `rls/policy-not-owner-scoped` (flagship) | **9.2%** (91 / 994) | **235** | **all 235 ground-truthed → precision 1.0, 0 residual FP** |
| `rls/table-without-rls` | 27.4% (273 / 998) | — | indicative (not audited to the same precision) |

The flagship owner-scope rule held **precision 1.0 on a fresh, larger corpus** (235 findings, every one a
genuine authenticated-only gap on re-clone) — the original "precision 1.0" was not a benchmark artifact.

**A 7th hardening iteration, surfaced by this very run.** The 1,000-repo scan exposed the *sibling*
`rls/anon-writable` rule over-firing: of 80 findings, **~68% (54) were false positives** — custom `auth.*()`
schema helpers (`auth.is_admin()`, `auth.email()`, `auth.user_role()`, `auth.org_id()`) and the list form
`auth.role() IN ('service_role', …)`, none of which an anon can satisfy. The classifier was hardened
(unrecognized `auth.*()` → `function-delegated`; `auth.role() IN (…)` → `role-delegated`), cutting
`anon-writable` from **80 → 26** **with zero recall loss on the flagship rule** (235 → 235 on a same-sample
re-scan). Both fixed classes are locked as regression fixtures. Of the 26 that still fire, **22 are genuinely
anon-satisfiable row-state predicates** and **4 are residual false positives** across three shapes an anon
cannot actually satisfy: `auth.uid() = '<hardcoded-uuid>'` (×2, documented and accepted) and — not yet
suppressed — the `(select auth.uid() as uid) is not null` and `(select auth.jwt() ->> 'email') = email`
wrapper forms, where the Supabase performance wrapper's `AS <alias>` defeats the session-proof / owner-bound
match. That `selectWrap` alias gap is tracked as a follow-up fix (with its own regression fixtures);
disclosing it keeps the precision figure honest rather than rounding it up.

Seven verification iterations, each surfacing a real-world false-positive (or false-negative) class that the
curated benchmark had missed:

1. `service_role` / admin-claim gates, `::cast`, `as` aliases mistaken for the gap.
2. jsonb `?`, `(select …)` wrappers, `coalesce(auth.uid(), …)`, `auth.uid() IS NULL`.
   → motivated the redesign to a **positive `SESSION_PROOF` gate** (only `auth.uid()/auth.jwt() IS NOT NULL`
   or `auth.role() = 'authenticated'` is the gap; everything else is suppressed, fail-secure).
3. A **false negative**: the `(select auth.role()) = 'authenticated'` wrapper — caught by an FN guard.
4. **Quoted identifiers** `"auth"."role"()` (pg_dump / declarative `supabase/schemas`) + `current_setting`.
5. A **cross-rule regression**: routing role gates to `unknown` made the sibling `rls/anon-writable` rule
   fire on `service_role` policies an anon can never satisfy — caught by auditing the secondary rule.
6. `auth.uid() IN (sender_id, receiver_id)` participant bindings.
7. *(2026-07-01, from the 1,000-repo run)* `lower(col) = lower(auth.jwt() ->> 'email')` case-insensitive
   owner bindings (flagship rule); custom `auth.*()` helpers and `auth.role() IN (…)` list gates wrongly
   read as anon-satisfiable by the sibling `rls/anon-writable` rule (the ~68% FP class above).

Every class above is now locked as a regression fixture:

- **False positives → must stay silent:** [`packages/scanner/fixtures/sql/good/rls-restrictive-and-owner-variants.sql`](../../packages/scanner/fixtures/sql/good/rls-restrictive-and-owner-variants.sql)
  and [`rls-quoted-and-identity-forms.sql`](../../packages/scanner/fixtures/sql/good/rls-quoted-and-identity-forms.sql).
- **Genuine gaps → must fire:** [`packages/scanner/fixtures/sql/vuln/rls-real-world-gaps.sql`](../../packages/scanner/fixtures/sql/vuln/rls-real-world-gaps.sql).
- The benchmark gate ([`packages/scanner/bench/gate.test.ts`](../../packages/scanner/bench/gate.test.ts)) enforces
  `precision = 1.0` over the whole corpus on every `pnpm test` (and thus CI).

## Reproduce

```bash
# 1. Authenticate the GitHub CLI (code search needs auth).
gh auth status

# 2. Build the Aegis CLI the study scans with.
pnpm --filter @aegiskit/cli build

# 3. Discover candidate repos (throttled to the code-search budget; ~4 min).
bash research/rls-precision-study/discover.sh        # -> data/repos.txt

# 4. Clone (shallow, sparse: supabase schema only) + scan each. N = how many.
python3 research/rls-precision-study/run.py 450       # -> data/rows.csv, data/results/*.json

# 5. Aggregate the rates (writes data/summary.md).
python3 research/rls-precision-study/aggregate.py
```

`data/` (clones, per-repo scanner JSON, repo lists, generated summary) is `.gitignore`d — only the
scripts, this methodology, and the distilled anonymized fixtures are committed.

## Corpus design & sampling

**Discovery.** `discover.sh` issues seven diversified GitHub *code-search* queries scoped to
`path:supabase/migrations|schemas` (the predicate keywords vary — `create policy`, `enable row level
security`, `auth.uid()`, `to authenticated`, `using (true)`, … — because one query caps at 1,000 results
and many files map to one repo). Results are deduplicated to unique `owner/repo` and **forks are excluded**
(`select(.fork == false)`; code search already skips forks by default). The 2026-06-28 run yielded
**2,230** unique non-fork repositories.

**Unit of analysis.** One repository. We clone shallow + sparse (only `supabase/migrations|schemas`),
concatenate the SQL, and scan it. The denominator is **repos that ship RLS** — ≥ 1 `CREATE POLICY` grepped
on the *checked-out SQL* as ground truth, **not** inferred from the search query. The numerator is repos
with ≥ 1 `rls/policy-not-owner-scoped` finding.

**Sampling.** Omitting `LIMIT` scans the whole pool (no sampling — preferred). With a `LIMIT`, `run.py`
now draws a **seeded random** sample (`SAMPLE_SEED`, reproducible). ⚠️ **The 2026-06-28 run that the
write-up cites predates this** and scanned the first 450 of the pool in alphabetical `owner/repo` order.
Alphabetical order is plausibly independent of whether a developer scopes RLS to owners, so we treat it as
an arbitrary (≈ random) 450 — but it is **not** a drawn random sample, and we disclose that rather than
imply one.

**Known selection biases (mixed directions — net is not assumed).**
- *Keyword discovery* over-represents repos whose SQL contains those idioms. Some (`to authenticated`,
  `auth.uid()`) also appear in *correct* owner-scoped policies, biasing the rate **down**; others
  (`using (true)`) correlate with permissive policies, biasing **up** — but mostly a *different*, secondary
  rule, not the 8.1% headline.
- *Public-migration skew* (see Ethics): committing migrations to public GitHub selects for more careful
  developers → the headline is a **lower bound**.

**Reproducibility stance.** Scripts, queries, seed, and date are committed, so the **method** reproduces.
The exact **population does not**: code-search results drift, and we deliberately do **not** commit the
resolved repo list (naming scanned repos conflicts with the anonymity caveat below). A re-run yields a
fresh population — and may surface new false-positive shapes that must be audited back to `precision = 1.0`
before any new rate is published.

## Ethics & honest caveats

- **Static, public-source only.** Computed from migration SQL (the authoritative schema) of public
  repositories. **No deployed endpoint is ever contacted** — no live probing, no unauthorized access.
- **Anonymized in any published output.** Rates are aggregate; no repository is named.
- **Lower bound, not upper.** Repos that commit Supabase *migrations* to public GitHub skew toward more
  careful developers. The most at-risk apps often never commit migrations or aren't public — so the true
  population rate is plausibly worse, not better.
- **"Not owner-scoped" ≠ "vulnerable".** A genuinely shared/lookup table legitimately uses an
  authenticated-only policy. The finding means *RLS authenticates but does not restrict rows to their owner
  — verify this is intended*; that is why the rule is medium severity and non-blocking.
- Aegis **never claims to find every vulnerability**. See [`docs/coverage.md`](../../docs/coverage.md) for
  exactly what it detects and what it deliberately does not.

## Responsible disclosure

This study reads only SQL already public, names no repository, and contacts no running system — so it
creates no new exposure and raises no unauthorized-access concern. The posture reflects that the headline
finding is **medium / "verify intent," not a confirmed exploit**:

- **Reporting a real issue (inbound).** Security reports for Aegis or this study go through
  [`SECURITY.md`](../../.github/SECURITY.md) (private advisory) — never a public issue.
- **"Am I in the data?" / "Scan mine."** Aggregate results cannot be deanonymized. Anyone can check their
  own app in seconds with `npx @aegiskit/cli scan`, which runs **entirely locally** and contacts no
  deployed app. That is the safe, self-serve path — we never probe a third party's live endpoints without
  written authorization.
- **Proactive notification.** Because the finding is medium and often *intended* (shared/lookup tables),
  blanket-contacting flagged repos would be mostly noise and reads as unsolicited; we publish
  aggregate-only and keep the self-check + private channel open, reserving direct, coordinated outreach for
  any case that is unambiguously high-harm.
- **Hard rules (non-negotiable).** No live probing of third-party systems without written authorization;
  no deanonymization; the resolved repo list is never published; we never claim exploitation we did not
  confirm.
