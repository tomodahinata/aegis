import { describe, expect, it } from 'vitest';
import {
  buildPlan,
  miniDiff,
  type RemediationItem,
  renderRemediationJson,
  renderRemediationPretty,
} from './remediation';

const autoItem: RemediationItem = {
  ruleId: 'csrf/missing-origin-check',
  severity: 'HIGH',
  confidence: 'medium',
  file: 'src/app/api/pay/route.ts',
  line: 3,
  problem: 'No origin check.',
  mode: 'auto',
  action: 'Wrap POST with secureRoute (origin check on)',
  docsUrl: 'https://aegis.dev/rules/csrf-missing-origin-check',
  diff: ' import x\n-export async function POST() {\n+export const POST = secureRoute(...)',
};

const guidedItem: RemediationItem = {
  ruleId: 'secrets/committed-literal',
  severity: 'HIGH',
  confidence: 'high',
  file: 'src/lib/env.ts',
  line: 2,
  problem: 'Hard-coded secret.',
  mode: 'guided',
  action: 'Move it to a server-only env var and rotate it.',
  docsUrl: 'https://aegis.dev/rules/secrets-committed-literal',
};

describe('miniDiff', () => {
  it('shows a changed middle line with one line of context each side', () => {
    expect(miniDiff('a\nb\nc', 'a\nB\nc')).toEqual([' a', '-b', '+B', ' c']);
  });

  it('represents a pure insertion', () => {
    expect(miniDiff('x', 'i\nx')).toEqual(['+i', ' x']);
  });
});

describe('buildPlan', () => {
  it('counts auto vs guided', () => {
    const plan = buildPlan([autoItem, guidedItem, guidedItem]);
    expect(plan.auto).toBe(1);
    expect(plan.guided).toBe(2);
    expect(plan.items).toHaveLength(3);
  });
});

describe('renderRemediationPretty', () => {
  const opts = { color: false, plain: false, applied: false };

  it('labels mode with TEXT and a glyph — never color alone (a11y)', () => {
    const out = renderRemediationPretty(buildPlan([autoItem, guidedItem]), opts);
    expect(out).toContain('AUTO ✎');
    expect(out).toContain('GUIDED ◆');
    expect(out).toContain('→ Fix:'); // preview verb
  });

  it('plain mode is label-prefixed with no glyphs', () => {
    const out = renderRemediationPretty(buildPlan([autoItem]), { ...opts, plain: true });
    expect(out).toContain('Mode: AUTO');
    expect(out).toContain('File: src/app/api/pay/route.ts:3');
    expect(out).not.toContain('✎');
  });

  it('switches to past tense when applied', () => {
    const out = renderRemediationPretty(buildPlan([autoItem]), { ...opts, applied: true });
    expect(out).toContain('✓ Applied:');
    expect(out).toContain('Applied  AUTO 1');
  });

  it('reports nothing to remediate for an empty plan', () => {
    expect(renderRemediationPretty(buildPlan([]), opts)).toContain('Nothing to remediate');
  });
});

describe('renderRemediationJson', () => {
  it('emits a stable machine-readable plan (the agent handoff)', () => {
    const parsed = JSON.parse(renderRemediationJson(buildPlan([autoItem, guidedItem])));
    expect(parsed.summary).toEqual({ auto: 1, guided: 1, total: 2 });
    expect(parsed.items[0].ruleId).toBe('csrf/missing-origin-check');
    expect(parsed.items[0].mode).toBe('auto');
    expect(parsed.items[1].mode).toBe('guided');
  });
});
