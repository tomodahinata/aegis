---
"@aegiskit/scanner": minor
"@aegiskit/cli": minor
---

scanner: detect RLS policies that gate on authentication but not row ownership.

- `rls/policy-not-owner-scoped` now also flags write-capable policies whose `WITH CHECK` predicate is authenticated-only even when `USING` is owner-bound (`FOR ALL … USING (auth.uid() = user_id) WITH CHECK (auth.uid() IS NOT NULL)`), where any logged-in user can insert or give away rows they do not own (CWE-639).
- `rls/exposed-table-access` correlates this authenticated-only case to the query site at **medium** confidence — it informs, it does not assert confirmed exposure, because the table may be intentionally shared.
- Predicate classification now ignores `auth.*` tokens that appear inside SQL comments or string literals (JWT-claim literals are preserved), removing a class of false positives, and is hardened against a quadratic-time blowup on adversarially long policy predicates.
- `crypto/weak-hash` no longer suppresses weak hashes used for auth-relevant identifiers (e.g. `cacheSessionToken`, `deviceFingerprint`), while keeping benign UUID/cache-key/asset-fingerprint uses suppressed.

cli: the pretty reporter prints a prioritized "Fix first" headline with a severity breakdown and sorts findings by severity → confidence → location. Engine, JSON, and SARIF output order are unchanged.
