import { readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan } from './engine';
import { ANALYSIS_ERROR_RULE } from './internal/analysis-error';
import type { Rule } from './rule';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

function filesIn(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...filesIn(full));
    } else if (/\.(?:ts|tsx|js|jsx)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

describe('scanner — vulnerable fixtures each trigger their rule', () => {
  const cases: ReadonlyArray<readonly [dir: string, ruleId: string]> = [
    ['csp-unsafe-inline', 'csp/unsafe-inline'],
    ['csp-nonce-unused', 'csp/nonce-minted-unused'],
    ['headers-missing', 'headers/missing-security-headers'],
    ['ratelimit-ai', 'ratelimit/missing-on-ai-route'],
    ['public-secret', 'env/public-secret'],
    ['secret-in-client', 'env/secret-in-client'],
    ['secret-reachable-from-client', 'env/secret-in-client'],
    ['service-role', 'supabase/service-role-outside-admin'],
    ['csrf', 'csrf/missing-origin-check'],
    ['dangerous-html', 'xss/dangerous-html-unsanitized'],
    ['secret-literal', 'secrets/committed-literal'],
    // Injection family (dataflow / taint).
    ['sqli-supabase', 'injection/sql'],
    ['ssrf-fetch', 'ssrf/tainted-fetch'],
    ['xss-dom-innerhtml', 'xss/tainted-dom-sink'],
    ['path-traversal', 'injection/path-traversal'],
    ['command-injection', 'injection/command'],
    ['open-redirect', 'redirect/open-redirect'],
    ['code-injection', 'injection/code'],
    // Cryptographic weaknesses + authorization.
    ['weak-random-token', 'crypto/insecure-randomness'],
    ['weak-hash', 'crypto/weak-hash'],
    ['timing-compare', 'crypto/non-constant-time-compare'],
    ['authz-missing-filter', 'authz/missing-access-filter'],
    ['idor-tainted-scope', 'authz/idor-tainted-scope'],
  ];

  for (const [dir, ruleId] of cases) {
    it(`flags ${ruleId}`, () => {
      const result = scan({ files: filesIn(join(FIXTURES, 'vuln', dir)) });
      const ruleIds = result.findings.map((finding) => finding.ruleId);
      expect(ruleIds).toContain(ruleId);
    });
  }
});

describe('scanner — the zero-false-positive trust gate', () => {
  it('produces ZERO findings across all known-good fixtures', () => {
    const result = scan({ files: filesIn(join(FIXTURES, 'good')) });
    // If this fails, the message prints the offending findings — the gate that protects trust.
    expect(result.findings).toEqual([]);
  });
});

describe('scanner — fixed false negatives', () => {
  it("flags 'unsafe-inline' in an array-split CSP fragment that names no directive", () => {
    const file = join(FIXTURES, 'vuln', 'csp-unsafe-inline', 'middleware.ts');
    const ruleIds = scan({ files: [file] }).findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('csp/unsafe-inline');
  });

  it('flags a destructured `const { SECRET } = process.env` in client-reachable code', () => {
    const file = join(FIXTURES, 'vuln', 'secret-in-client', 'destructured.tsx');
    const ruleIds = scan({ files: [file] }).findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('env/secret-in-client');
  });
});

describe('scanner — per-file isolation (fail secure)', () => {
  it('skips an unreadable file with a LOW finding instead of aborting the whole scan', () => {
    const good = '/app/api/x/route.ts';
    const bad = '/app/api/broken/route.ts';
    const readFile = (path: string): string => {
      if (path === bad) {
        throw new Error('EACCES: permission denied');
      }
      return "export async function GET() { return supabase.from('orders').select('*'); }";
    };

    // One bad file must NOT throw or discard the good file's analysis.
    const result = scan({ files: [bad, good], readFile });
    expect(result.scannedFiles).toBe(1);

    // The coverage gap is surfaced, not silently swallowed (fail open).
    const analysisError = result.findings.find((f) => f.ruleId === ANALYSIS_ERROR_RULE);
    expect(analysisError).toBeDefined();
    expect(analysisError?.file).toBe(bad);
    expect(analysisError?.severity).toBe('LOW');
  });
});

describe('scanner — per-rule isolation (fail secure)', () => {
  it('a rule that throws becomes a LOW finding instead of aborting the whole scan', () => {
    const boom: Rule = {
      meta: {
        id: 'test/throws',
        title: 'always throws',
        severity: 'HIGH',
        docsUrl: 'https://example.test',
      },
      appliesTo: () => true,
      check: () => {
        throw new Error('pathological AST');
      },
    };
    const ok: Rule = {
      meta: {
        id: 'test/ok',
        title: 'always reports',
        severity: 'LOW',
        docsUrl: 'https://example.test',
      },
      appliesTo: () => true,
      check: (ctx) =>
        ctx.report({
          node: ctx.file.sourceFile,
          message: 'present',
          remediation: 'none',
          confidence: 'high',
        }),
    };

    const file = '/app/api/x/route.ts';
    const result = scan({
      files: [file],
      readFile: () => 'export async function GET() { return 1; }',
      rules: [boom, ok],
    });

    // The throw is surfaced (fail secure), not silently swallowed…
    const ruleError = result.findings.find((f) => f.ruleId === ANALYSIS_ERROR_RULE);
    expect(ruleError).toBeDefined();
    expect(ruleError?.severity).toBe('LOW');
    expect(ruleError?.message).toContain('test/throws');
    // …and the other rule still ran — one bad rule does not discard the rest of the scan.
    expect(result.findings.some((f) => f.ruleId === 'test/ok')).toBe(true);
  });
});
