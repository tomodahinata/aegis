/**
 * Single source of truth for the labeled fixture corpus: which rule(s) each vulnerable fixture must
 * trigger. Imported by both the test suite (`scan.test.ts` / `scan-sql.test.ts`) AND the precision/
 * recall benchmark (`bench/`), so the two can never drift. Good fixtures are implicit: every directory
 * under `fixtures/good` and `fixtures/sql/good` must produce ZERO findings (the trust gate).
 */

export interface FixtureLabel {
  /** Directory name under `fixtures/vuln` (TS) or `fixtures/sql/vuln` (SQL). */
  readonly dir: string;
  /** Every ruleId that MUST fire for this fixture (≥1). A miss is a false negative (recall). */
  readonly expect: readonly string[];
  /**
   * ruleIds that are CORRECT-but-incidental here, so they do not count against precision — e.g. the SQL
   * injection fixture also legitimately lacks a visible auth filter. Anything fired that is in neither
   * `expect` nor `allow` is surfaced by the benchmark as "unexpected" (informational, never scored).
   */
  readonly allow?: readonly string[];
}

/** One entry per directory under `fixtures/vuln`. Kept exhaustive by a meta-test in `scan.test.ts`. */
export const TS_LABELS: readonly FixtureLabel[] = [
  { dir: 'csp-unsafe-inline', expect: ['csp/unsafe-inline'] },
  // The nonce-unused fixture also (correctly) carries 'unsafe-inline' — an allowed secondary finding.
  { dir: 'csp-nonce-unused', expect: ['csp/nonce-minted-unused'], allow: ['csp/unsafe-inline'] },
  { dir: 'headers-missing', expect: ['headers/missing-security-headers'] },
  { dir: 'ratelimit-ai', expect: ['ratelimit/missing-on-ai-route'] },
  { dir: 'public-secret', expect: ['env/public-secret'] },
  { dir: 'secret-in-client', expect: ['env/secret-in-client'] },
  { dir: 'secret-reachable-from-client', expect: ['env/secret-in-client'] },
  // The service-role key is also a secret reaching client-reachable code — an allowed secondary finding.
  { dir: 'service-role', expect: ['supabase/service-role-outside-admin'], allow: ['env/secret-in-client'] },
  { dir: 'csrf', expect: ['csrf/missing-origin-check'] },
  { dir: 'dangerous-html', expect: ['xss/dangerous-html-unsanitized'] },
  { dir: 'secret-literal', expect: ['secrets/committed-literal'] },
  // Injection family (dataflow / taint).
  { dir: 'sqli-supabase', expect: ['injection/sql'], allow: ['authz/missing-access-filter'] },
  { dir: 'ssrf-fetch', expect: ['ssrf/tainted-fetch'] },
  { dir: 'xss-dom-innerhtml', expect: ['xss/tainted-dom-sink'] },
  { dir: 'path-traversal', expect: ['injection/path-traversal'] },
  { dir: 'command-injection', expect: ['injection/command'] },
  { dir: 'open-redirect', expect: ['redirect/open-redirect'] },
  { dir: 'code-injection', expect: ['injection/code'] },
  // Cryptographic weaknesses + authorization.
  { dir: 'weak-random-token', expect: ['crypto/insecure-randomness'] },
  { dir: 'weak-hash', expect: ['crypto/weak-hash'] },
  { dir: 'timing-compare', expect: ['crypto/non-constant-time-compare'] },
  { dir: 'authz-missing-filter', expect: ['authz/missing-access-filter'] },
  { dir: 'idor-tainted-scope', expect: ['authz/idor-tainted-scope'] },
];

/**
 * The SQL corpus is a single directory (`fixtures/sql/vuln`) whose migrations together exercise every
 * RLS rule — modeled as one label whose `expect` set is the full RLS rule roster.
 */
export const SQL_LABELS: readonly FixtureLabel[] = [
  {
    dir: 'vuln',
    expect: [
      'rls/table-without-rls',
      'rls/security-definer-search-path',
      'rls/write-policy-without-check',
      'rls/permissive-write-policy',
      'rls/policy-not-owner-scoped',
      'rls/anon-table-grant',
    ],
  },
];
