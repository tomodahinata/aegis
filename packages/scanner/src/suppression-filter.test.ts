import { describe, expect, it } from 'vitest';
import { scan } from './engine';

const PATH = '/proj/src/env.ts';
const VULN = 'export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n';

function scanSource(source: string) {
  return scan({ files: [PATH], readFile: () => source });
}

describe('scan() — inline suppression', () => {
  it('reports the finding when not suppressed', () => {
    const result = scanSource(VULN);
    expect(result.findings.map((f) => f.ruleId)).toContain('env/public-secret');
    expect(result.suppressedCount).toBe(0);
  });

  it('mutes the finding with a reasoned disable-next-line and counts it', () => {
    const result = scanSource(
      `// aegis-disable-next-line env/public-secret -- example key in a fixture\n${VULN}`,
    );
    expect(result.findings.map((f) => f.ruleId)).not.toContain('env/public-secret');
    expect(result.suppressedCount).toBe(1);
  });

  it('still mutes a reasonless disable but surfaces it as a finding', () => {
    const result = scanSource(`// aegis-disable-next-line env/public-secret\n${VULN}`);
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).not.toContain('env/public-secret');
    expect(ids).toContain('aegis/suppression-without-reason');
    expect(result.suppressedCount).toBe(1);
  });

  it('keeps suppressed findings (flagged) under showSuppressed', () => {
    const result = scan({
      files: [PATH],
      readFile: () => `// aegis-disable-next-line env/public-secret -- ok\n${VULN}`,
      showSuppressed: true,
    });
    const finding = result.findings.find((f) => f.ruleId === 'env/public-secret');
    expect(finding?.suppressed).toBe(true);
  });
});
