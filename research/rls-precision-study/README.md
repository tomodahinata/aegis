# Supabase RLS precision study

A reproducible field study that measured — and then hardened — the precision of Aegis's flagship rule
`rls/policy-not-owner-scoped` against **real production code**, not curated fixtures. It is the evidence
behind the claim that Aegis's zero-false-positive design holds on the shapes real Supabase apps ship.

> **Why this exists.** A curated benchmark reporting `precision 1.0` does **not** guarantee real-world
> precision. This study scanned a large public corpus, audited every finding, and drove the rule from a
> false-positive-laden raw rate to a verified-genuine one — distilling each false-positive class into a
> permanent regression fixture so the gain can never silently regress.

## Headline (2026-06-28, 450 public repos with `supabase/migrations|schemas`)

| | Flag rate | Findings | What the iteration fixed |
|---|---:|---:|---|
| raw (pre-hardening) | 19.3% | 573 | — (a full audit found **~83% were false positives**) |
| after hardening | **8.1%** | **99** | **0 residual false positives** — every finding ground-truthed as a genuine authenticated-only gap |

Six verification iterations, each surfacing a real-world false-positive (or false-negative) class that the
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
