import { describe, expect, it } from 'vitest';
import { toJson, toTable } from './format';
import { computeMetrics } from './metrics';

const sample = computeMetrics({
  vuln: [
    { corpus: 'ts', dir: 'a', expect: ['r1'], allow: [], fired: ['r1'] },
    { corpus: 'sql', dir: 'vuln', expect: ['r2'], allow: [], fired: [] },
  ],
  good: [
    { corpus: 'ts', dir: 'g', fired: ['r3'] },
    { corpus: 'sql', dir: 'good', fired: [] },
  ],
});

describe('benchmark formatters', () => {
  it('renders a deterministic JSON snapshot', () => {
    expect(toJson(sample)).toMatchSnapshot();
  });

  it('renders a deterministic table snapshot', () => {
    expect(toTable(sample)).toMatchSnapshot();
  });

  it('JSON carries no timing and no absolute paths (machine-stable)', () => {
    const json = toJson(sample);
    expect(json).not.toContain('durationMs');
    expect(json).not.toContain('/Users/');
    expect(JSON.parse(json).schema).toBe(1);
  });
});
