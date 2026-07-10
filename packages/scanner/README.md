# @aegiskit/scanner

The static-analysis engine behind [`@aegiskit/cli`](../cli). It finds the security gaps a runtime library can't fix — grounded in real vibe-coded Next.js/Supabase mistakes — while keeping false positives low.

Most people use this via the `aegis` CLI; import it directly to embed scanning in your own tooling.

```ts
import { scan, toSarif } from '@aegiskit/scanner';

const result = scan({ files: ['/abs/app/api/ai/route.ts', /* … */] });
console.log(result.summary); // { BLOCKER, HIGH, MEDIUM, LOW, INFO }
const sarif = toSarif(result);
```

## How it stays trustworthy

- Parses TypeScript/JSX and classifies each file's **runtime context** (server/client/edge) and **client-reachability** from the import graph — so "secret read in client code" is AST evidence, not a filename guess.
- Each finding carries a **confidence**; the CLI fails CI only on high-confidence findings by default.
- A **zero-false-positive gate** in the test suite asserts that a corpus of known-good code produces *no* findings — a new rule that lights up good code fails our own build.

## The built-in rules

`csp/unsafe-inline` · `csp/nonce-minted-unused` · `headers/missing-security-headers` · `ratelimit/missing-on-ai-route` · `env/public-secret` · `env/secret-in-client` · `supabase/service-role-outside-admin` · `csrf/missing-origin-check` · plus the full `rls/*` SQL family (`rls/table-without-rls`, `rls/policy-not-owner-scoped`, `rls/anon-writable`, …) — see [`docs/coverage.md`](../../docs/coverage.md) for the complete, generated rule registry.

Adding a rule is one file implementing the `Rule` interface.

## License

MIT
