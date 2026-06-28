import { describe, expect, it } from 'vitest';
import type { Finding, ScanResult, Severity, SourceRange } from '../types';
import { emptySummary } from '../types';
import { toSarif } from './sarif';

const RANGE: SourceRange = { startLine: 1, startColumn: 1, endLine: 1, endColumn: 10 };

const BASE: Finding = {
  ruleId: 'env/secret-in-client',
  severity: 'BLOCKER',
  confidence: 'high',
  message: 'A secret is read in client-reachable code.',
  file: '/app/widget.tsx',
  range: RANGE,
  docsUrl: 'https://github.com/tomodahinata/aegis/rules/env-secret-in-client',
  remediation: 'Move the read server-side.',
};

function finding(overrides: Partial<Finding> = {}): Finding {
  return { ...BASE, ...overrides };
}

function result(findings: Finding[]): ScanResult {
  return {
    findings,
    passes: [],
    summary: emptySummary(),
    scannedFiles: 1,
    suppressedCount: 0,
    durationMs: 0,
  };
}

interface SarifRule {
  readonly id: string;
  readonly properties: { readonly 'security-severity': string };
}
interface SarifThreadFlowLocation {
  readonly location: {
    readonly message: { readonly text: string };
    readonly physicalLocation: { readonly region: { readonly startLine: number } };
  };
}
interface SarifPhysicalLocation {
  readonly artifactLocation: { readonly uri: string };
  readonly region?: { readonly startLine: number };
}
interface SarifResult {
  readonly level: 'error' | 'warning' | 'note';
  readonly locations: ReadonlyArray<{ readonly physicalLocation: SarifPhysicalLocation }>;
  readonly partialFingerprints: { readonly aegisFingerprint: string };
  readonly codeFlows?: ReadonlyArray<{
    readonly threadFlows: ReadonlyArray<{ readonly locations: readonly SarifThreadFlowLocation[] }>;
  }>;
}
interface SarifDoc {
  readonly $schema: string;
  readonly version: string;
  readonly runs: ReadonlyArray<{
    readonly tool: { readonly driver: { readonly rules: readonly SarifRule[] } };
    readonly results: readonly SarifResult[];
  }>;
}

function parse(findings: Finding[]): SarifDoc {
  return JSON.parse(toSarif(result(findings))) as SarifDoc;
}

function run(doc: SarifDoc) {
  const r = doc.runs[0];
  if (!r) {
    throw new Error('expected one run');
  }
  return r;
}

describe('toSarif — SARIF 2.1.0 shape', () => {
  it('emits a valid SARIF 2.1.0 envelope', () => {
    const doc = parse([finding()]);
    expect(doc.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs).toHaveLength(1);
    expect(run(doc).results).toHaveLength(1);
  });

  it('declares exactly one rule entry per unique ruleId', () => {
    const doc = parse([
      finding({ ruleId: 'env/secret-in-client', evidence: 'A' }),
      finding({ ruleId: 'env/secret-in-client', evidence: 'B' }),
      finding({ ruleId: 'csp/unsafe-inline', severity: 'HIGH', evidence: 'C' }),
    ]);
    const ids = run(doc).tool.driver.rules.map((rule) => rule.id);
    expect(ids).toEqual(['env/secret-in-client', 'csp/unsafe-inline']);
    // …while every finding still surfaces as its own result.
    expect(run(doc).results).toHaveLength(3);
  });
});

describe('toSarif — level mapping', () => {
  const cases: ReadonlyArray<readonly [Severity, 'error' | 'warning' | 'note']> = [
    ['BLOCKER', 'error'],
    ['HIGH', 'error'],
    ['MEDIUM', 'warning'],
    ['LOW', 'note'],
    ['INFO', 'note'],
  ];
  for (const [severity, level] of cases) {
    it(`maps ${severity} → ${level}`, () => {
      const doc = parse([finding({ severity })]);
      expect(run(doc).results[0]?.level).toBe(level);
    });
  }
});

describe('toSarif — security-severity mapping', () => {
  const cases: ReadonlyArray<readonly [Severity, string]> = [
    ['BLOCKER', '9.5'],
    ['HIGH', '8.0'],
    ['MEDIUM', '5.0'],
    ['LOW', '3.0'],
    ['INFO', '1.0'],
  ];
  for (const [severity, score] of cases) {
    it(`maps ${severity} → ${score}`, () => {
      const doc = parse([finding({ severity })]);
      expect(run(doc).tool.driver.rules[0]?.properties['security-severity']).toBe(score);
    });
  }
});

describe('toSarif — partialFingerprints stability', () => {
  const fp = (doc: SarifDoc, i: number): string | undefined =>
    run(doc).results[i]?.partialFingerprints.aegisFingerprint;

  it('produces the SAME fingerprint when only the start line shifts (shared evidence)', () => {
    const doc = parse([
      finding({ range: { ...RANGE, startLine: 5 }, evidence: 'STRIPE_SECRET_KEY' }),
      finding({ range: { ...RANGE, startLine: 42 }, evidence: 'STRIPE_SECRET_KEY' }),
    ]);
    expect(fp(doc, 0)).toBe(fp(doc, 1));
  });

  it('falls back to startLine when no evidence is present', () => {
    // Omit `evidence` entirely (exactOptionalPropertyTypes forbids assigning `undefined`).
    const doc = parse([
      finding({ range: { ...RANGE, startLine: 5 } }),
      finding({ range: { ...RANGE, startLine: 9 } }),
    ]);
    expect(fp(doc, 0)).not.toBe(fp(doc, 1));
  });
});

describe('toSarif — dataflow codeFlows', () => {
  const traced = finding({
    ruleId: 'injection/sql',
    trace: [
      { kind: 'source', label: 'tainted by request body', range: { ...RANGE, startLine: 4 } },
      { kind: 'sink', label: 'reaches supabase.rpc()', range: { ...RANGE, startLine: 9 } },
    ],
  });

  it('emits a threadFlow with one location per trace step, labelled and located', () => {
    const locations = run(parse([traced])).results[0]?.codeFlows?.[0]?.threadFlows[0]?.locations;
    expect(locations).toHaveLength(2);
    expect(locations?.[0]?.location.message.text).toBe('tainted by request body');
    expect(locations?.[0]?.location.physicalLocation.region.startLine).toBe(4);
  });

  it('omits codeFlows entirely for a finding without a trace (backward compatible)', () => {
    expect(run(parse([finding()])).results[0]?.codeFlows).toBeUndefined();
  });
});

describe('toSarif — dynamic (DAST) findings', () => {
  it('uses the URL as the artifact uri and omits the source region', () => {
    const doc = parse([
      finding({
        ruleId: 'dast/security-headers',
        file: 'http://localhost:3000/api/x',
        target: { kind: 'http-request', method: 'GET', path: '/api/x', response: { status: 200 } },
      }),
    ]);
    const location = run(doc).results[0]?.locations[0]?.physicalLocation;
    expect(location?.artifactLocation.uri).toBe('http://localhost:3000/api/x');
    expect(location?.region).toBeUndefined();
  });

  it('keeps a source region for a static finding (backward compatible)', () => {
    const location = run(parse([finding()])).results[0]?.locations[0]?.physicalLocation;
    expect(location?.region?.startLine).toBe(1);
  });
});
