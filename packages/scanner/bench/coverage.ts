/**
 * The coverage matrix generator — the machine source of `docs/coverage.md`. It turns Aegis's "never claim
 * to find everything" principle into a SHIPPED, drift-proof artifact: a table derived from the live rule
 * registries (`ALL_RULES` + `ALL_SQL_RULES`) plus an explicit, curated statement of what Aegis does NOT
 * detect. `coverage.test.ts` asserts (a) every rule is classified here and (b) the committed markdown equals
 * this output — so the doc can never silently drift from the code. Run `pnpm --filter @aegiskit/scanner
 * coverage:matrix:write` to regenerate.
 *
 * Why the analysis-kind lives here, not in `RuleMeta`: it is documentation metadata consumed only by this
 * matrix, never at scan time. Keeping it out of the runtime rule type preserves a minimal runtime surface
 * (SRP); the completeness test gives the same "no rule ships unclassified" guarantee as a required field.
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_RULES } from '../src/rules';
import { ALL_SQL_RULES } from '../src/sql-rules';
import type { Severity } from '../src/types';

/**
 * How a rule reaches its verdict — the single most important honesty signal for a reader:
 *  - `taint`     — interprocedural-aware source→sink dataflow. Hard evidence; the source→sink path is shown.
 *  - `semantic`  — structural AST / SQL-predicate / regex-complexity analysis. Hard evidence.
 *  - `heuristic` — a low-noise pattern/name match that surfaces a spot for human review. Advisory, not proof.
 */
export type AnalysisKind = 'taint' | 'semantic' | 'heuristic';

/** Exhaustive (enforced by `coverage.test.ts`) classification of every built-in rule by analysis method. */
const RULE_ANALYSIS: Readonly<Record<string, AnalysisKind>> = {
  // Taint — source→sink dataflow.
  'injection/sql': 'taint',
  'injection/code': 'taint',
  'injection/command': 'taint',
  'injection/path-traversal': 'taint',
  'ssrf/tainted-fetch': 'taint',
  'xss/tainted-dom-sink': 'taint',
  'redirect/open-redirect': 'taint',
  'sanitize/incomplete-escape': 'taint',
  'authz/idor-tainted-scope': 'taint',
  // Semantic — AST / SQL-predicate / regex-complexity reasoning.
  'csp/nonce-minted-unused': 'semantic',
  'dom/postmessage-origin-missing': 'semantic',
  'redos/super-linear-regex': 'semantic',
  'redos/quadratic-regex': 'semantic',
  'rls/table-without-rls': 'semantic',
  'rls/security-definer-search-path': 'semantic',
  'rls/write-policy-without-check': 'semantic',
  'rls/permissive-write-policy': 'semantic',
  'rls/policy-not-owner-scoped': 'semantic',
  'rls/anon-table-grant': 'semantic',
  'rls/anon-writable': 'semantic',
  // Heuristic — pattern/name/entropy match; advisory review prompt.
  'csp/unsafe-inline': 'heuristic',
  'headers/missing-security-headers': 'heuristic',
  'ratelimit/missing-on-ai-route': 'heuristic',
  'env/public-secret': 'heuristic',
  'env/secret-in-client': 'heuristic',
  'supabase/service-role-outside-admin': 'heuristic',
  'csrf/missing-origin-check': 'heuristic',
  'xss/dangerous-html-unsanitized': 'heuristic',
  'secrets/committed-literal': 'heuristic',
  'crypto/insecure-randomness': 'heuristic',
  'crypto/weak-hash': 'heuristic',
  'crypto/non-constant-time-compare': 'heuristic',
  'authz/missing-access-filter': 'heuristic',
};

/** Human category, derived from the rule-id namespace (single source: the id). */
const CATEGORY: Readonly<Record<string, string>> = {
  injection: 'Injection',
  ssrf: 'SSRF',
  xss: 'Cross-site scripting (XSS)',
  redirect: 'Open redirect',
  sanitize: 'Output encoding',
  authz: 'Authorization / IDOR',
  rls: 'Supabase RLS / database authorization',
  crypto: 'Cryptography',
  secrets: 'Hard-coded secrets',
  env: 'Secret exposure (environment)',
  csp: 'Content Security Policy',
  csrf: 'CSRF',
  headers: 'Security headers',
  ratelimit: 'Rate limiting',
  dom: 'Cross-window messaging',
  supabase: 'Supabase service-role',
};

const ANALYSIS_LABEL: Readonly<Record<AnalysisKind, string>> = {
  taint: 'Taint (dataflow)',
  semantic: 'Semantic',
  heuristic: 'Heuristic (advisory)',
};

export interface CoverageRow {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly severity: Severity;
  readonly analysis: AnalysisKind;
  readonly owasp: string;
}

function categoryOf(id: string): string {
  const ns = id.split('/')[0] ?? id;
  return CATEGORY[ns] ?? ns;
}

/** Every built-in rule id (TS + SQL), in registry order — the authority for the completeness test. */
export function allRuleIds(): readonly string[] {
  return [...ALL_RULES.map((r) => r.meta.id), ...ALL_SQL_RULES.map((r) => r.meta.id)];
}

/** The classification keys — so the test can assert there are no orphan entries either. */
export function classifiedRuleIds(): readonly string[] {
  return Object.keys(RULE_ANALYSIS);
}

/** Build the matrix rows from the live registries; sorted by category then id for a stable doc. */
export function buildCoverage(): readonly CoverageRow[] {
  const metas = [...ALL_RULES.map((r) => r.meta), ...ALL_SQL_RULES.map((r) => r.meta)];
  return metas
    .map((m) => ({
      id: m.id,
      title: m.title,
      category: categoryOf(m.id),
      severity: m.severity,
      // Non-null asserted via the completeness test; `?? 'heuristic'` keeps render total if a future rule
      // slips through locally (the test, not a silent fallback, is the real guard).
      analysis: RULE_ANALYSIS[m.id] ?? 'heuristic',
      owasp: m.owasp ?? '—',
    }))
    .sort((a, b) => a.category.localeCompare(b.category) || a.id.localeCompare(b.id));
}

function table(rows: readonly CoverageRow[]): string {
  const head = '| Rule | Detects | Severity | Method | OWASP |\n|---|---|---|---|---|';
  const body = rows
    .map(
      (r) =>
        `| \`${r.id}\` | ${r.title} | ${r.severity} | ${ANALYSIS_LABEL[r.analysis]} | ${r.owasp} |`,
    )
    .join('\n');
  return `${head}\n${body}`;
}

/** Render the complete `docs/coverage.md`. The curated prose lives here so the file is fully regenerable. */
export function renderCoverage(rows: readonly CoverageRow[]): string {
  const counts = { taint: 0, semantic: 0, heuristic: 0 } as Record<AnalysisKind, number>;
  for (const r of rows) counts[r.analysis] += 1;

  return `<!-- GENERATED by packages/scanner/bench/coverage.ts — do not edit by hand.
     Run \`pnpm --filter @aegiskit/scanner coverage:matrix:write\` to regenerate. -->

# Aegis coverage matrix — what it detects, and what it does not

> **Aegis does not — and cannot — find every vulnerability.** No static analyzer can (it is undecidable in
> general), and any tool that claims to is dangerous: it breeds false confidence, the worst security
> outcome. Aegis instead detects a precise set of high-impact classes with a **zero-false-positive design**
> (the benchmark holds precision at 1.0), and tells you exactly what it leaves to secure design, code
> review, and other tools. This page is generated from the live rule registry, so it never drifts from what
> ships.

## How to read this

Every finding is one of three **methods**, ordered by strength of evidence:

- **Taint (dataflow)** — a proven source→sink path (the path is attached to the finding). Hard evidence.
- **Semantic** — structural AST / SQL-predicate / regex-complexity analysis. Hard evidence.
- **Heuristic (advisory)** — a low-noise pattern or name match that surfaces a spot to review. It is a
  prompt, not proof; these are reported at medium confidence and **do not fail CI by default**.

Built-in rules: **${rows.length}** total — ${counts.taint} taint, ${counts.semantic} semantic, ${counts.heuristic} heuristic. Dynamic confirmation (below) can upgrade a static finding to "confirmed".

## Rules

${table(rows)}

## Dynamic confirmation (DAST · \`@aegiskit/dast\`)

Aegis can probe a running app to **confirm** static findings at runtime — a matched dynamic result upgrades
the correlated static finding's confidence to *high* and attaches the HTTP exchange. Probes: reflected XSS,
SQL injection, open redirect, SSRF (out-of-band canary), missing security headers, error disclosure,
rate-limit burst, and — with supplied test identities — auth-required and IDOR. All probes are
non-destructive by default, off-origin requests are blocked, and a request budget bounds every run.

## What Aegis deliberately does NOT detect

These are out of scope **by design** (fail-secure: Aegis prefers a false negative to a false positive).
For each, use the noted complement:

- **Cross-file / multi-hop data flows.** Taint analysis is intraprocedural with depth-1 helper resolution;
  a flow that crosses several modules is not tracked. → Pair with a deep SAST (Semgrep, CodeQL) for
  whole-program flows.
- **Business-logic & workflow flaws** (price tampering, broken state machines, multi-step bypasses). No
  static tool infers intent. → Threat modeling + manual review + targeted DAST.
- **Authorization correctness in the general case.** Aegis proves request-scoped IDOR (\`authz/idor-tainted-scope\`)
  and Supabase RLS owner-scoping (\`rls/*\`) precisely, and flags "no visible auth check" as an advisory
  prompt — but it cannot decide arbitrary authorization logic. → Manual review of access decisions.
- **Runtime-only issues** (misconfigured production headers, live auth bypass) unless you run the DAST
  probes against a deployed instance.
- **Dependency / supply-chain CVEs and license risk.** → \`npm/pnpm audit\`, OSV, Socket, Dependabot.
- **Infrastructure, container, and cloud posture.** → Dedicated CSPM/IaC scanners.

Aegis automates the common, high-impact controls and **complements** secure design — it does not replace it.

---
*Generated from \`packages/scanner/src/rules\` + \`packages/scanner/src/sql-rules\` via
\`packages/scanner/bench/coverage.ts\`. To change this page, change a rule (or its classification) and run
\`pnpm --filter @aegiskit/scanner coverage:matrix:write\`.*
`;
}

const DOC_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  'docs',
  'coverage.md',
);

/** The canonical markdown for the current rule set. */
export function coverageMarkdown(): string {
  return renderCoverage(buildCoverage());
}

function main(): void {
  if (process.argv.includes('--write')) {
    writeFileSync(DOC_PATH, coverageMarkdown());
    process.stdout.write(`Updated ${DOC_PATH}\n`);
    return;
  }
  process.stdout.write(coverageMarkdown());
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}

export { DOC_PATH };
