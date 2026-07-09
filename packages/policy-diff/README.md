# @aegiskit/policy-diff

Semantic access diff for Supabase RLS migrations: compare the access-control surface (policies, RLS
state, table grants) of two migration states and get, in plain language, **who can newly read or
write what** — for PR review, CI gating, and change-management evidence.

## Install

```bash
pnpm add @aegiskit/policy-diff @aegiskit/scanner
```

`@aegiskit/scanner` is a peer — it supplies `buildRlsModel` and `SqlSource`. Most users get this
wired for free via the [`aegis diff`](../cli) CLI and the [GitHub Action](../../action.yml); import
this package directly only to build a custom gate.

```ts
import { buildRlsModel } from '@aegiskit/scanner';
import { diffAccess, renderDeltaMarkdown, summarizeDeltas } from '@aegiskit/policy-diff';

const base = buildRlsModel(baseSources); // supabase/migrations/**.sql at the base ref
const head = buildRlsModel(headSources); // …at the head ref

const deltas = diffAccess(base, head, { trustedFunctions: ['public.is_member'] });
console.log(renderDeltaMarkdown(deltas, { baseRef: 'main', headRef: 'feat/x' }));
summarizeDeltas(deltas).conclusion; // 'no-change' | 'neutral' | 'attention' | 'action-required'
```

## Trust contract

- **`widening`** is claimed only when the after-rows are a superset-or-equal of the before-rows
  under the class lattice (`none ⊂ own/state/delegated ⊂ all`).
- **`narrowing`** only when they are a subset-or-equal — a "safe" verdict never papers over a
  possible widening.
- Everything unverifiable — custom functions off the `trustedFunctions` allowlist, incomparable
  class moves (owner-scope ↔ row-state ↔ membership check), statements the model recorded as
  uninterpreted (`NO FORCE`, partial `REVOKE`, policies on unmodeled schemas, exotic quoting) — is
  **`requires-review`**. The diff fails closed: it may ask a human to look, it never says
  "no change" when it cannot know.

## Honest scope

This reasons about the *shape* of predicates over repo-managed SQL. It does not know your data
model or business rules, does not see policies changed outside migrations (e.g. via the Supabase
dashboard), and a clean diff means "no access-relevant change detected in the modeled surface" —
never "this migration is safe". It complements review; it does not replace it.
