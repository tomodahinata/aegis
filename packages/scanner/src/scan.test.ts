import { readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { TS_LABELS } from '../fixtures/labels';
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
  for (const label of TS_LABELS) {
    it(`flags ${label.expect.join(', ')} (${label.dir})`, () => {
      const result = scan({ files: filesIn(join(FIXTURES, 'vuln', label.dir)) });
      const ruleIds = result.findings.map((finding) => finding.ruleId);
      for (const ruleId of label.expect) {
        expect(ruleIds).toContain(ruleId);
      }
    });
  }

  it('labels cover every vuln fixture directory (no fixture left unlabeled)', () => {
    const labeled = new Set(TS_LABELS.map((l) => l.dir));
    const dirs = readdirSync(join(FIXTURES, 'vuln')).filter((d) =>
      statSync(join(FIXTURES, 'vuln', d)).isDirectory(),
    );
    expect([...labeled].sort()).toEqual([...dirs].sort());
  });
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

describe('scanner — "use server" Server Actions are a client-bundle barrier', () => {
  const billing = '/app/billing.ts';
  const action = '/app/lib/action.ts';
  const form = '/app/form.tsx';
  const sources: Record<string, string> = {
    [billing]: 'export const getStripe = () => process.env.STRIPE_SECRET_KEY ?? "";',
    [form]:
      "'use client';\nimport { charge } from './lib/action';\nexport const F = () => (typeof charge === 'function' ? 'y' : 'n');",
  };
  const scanWith = (actionSource: string): string[] =>
    scan({
      files: [billing, action, form],
      readFile: (p) => ({ ...sources, [action]: actionSource })[p] ?? '',
    }).findings.map((f) => f.ruleId);

  it('does NOT flag a secret reached only through a Server Action (RPC, never client-bundled)', () => {
    const ruleIds = scanWith(
      "'use server';\nimport { getStripe } from '../billing';\nexport async function charge() { return getStripe(); }",
    );
    expect(ruleIds).not.toContain('env/secret-in-client');
  });

  it('still flags the same secret when the boundary module is NOT a Server Action (proves the test)', () => {
    const ruleIds = scanWith(
      "import { getStripe } from '../billing';\nexport function charge() { return getStripe(); }",
    );
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
