import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

function idsFor(path: string, source: string, ruleId: string): string[] {
  return scan({ files: [path], readFile: () => source })
    .findings.filter((f) => f.ruleId === ruleId)
    .map((f) => f.ruleId);
}

function findingFor(path: string, source: string, ruleId: string) {
  return scan({ files: [path], readFile: () => source }).findings.find((f) => f.ruleId === ruleId);
}

const XSS = 'xss/dangerous-html-unsanitized';

describe('xss/dangerous-html-unsanitized', () => {
  it('flags an unsanitized __html source (high confidence)', () => {
    const finding = findingFor(
      '/a/post.tsx',
      'export const X = (p: { bio: string }) => <div dangerouslySetInnerHTML={{ __html: p.bio }} />;',
      XSS,
    );
    expect(finding?.confidence).toBe('high');
  });

  it('passes JSON.stringify (the json-ld pattern)', () => {
    expect(
      idsFor(
        '/a/ld.tsx',
        'export const X = (d: object) => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(d) }} />;',
        XSS,
      ),
    ).toHaveLength(0);
  });

  it('passes a sanitizer call and a static literal', () => {
    expect(
      idsFor(
        '/a/s.tsx',
        'export const X = (b: string) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(b) }} />;',
        XSS,
      ),
    ).toHaveLength(0);
    expect(
      idsFor(
        '/a/c.tsx',
        "export const X = () => <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />;",
        XSS,
      ),
    ).toHaveLength(0);
  });
});

const SECRETS = 'secrets/committed-literal';
const STRIPE = "export const k = 'sk_live_FAKEnotReal9';";

describe('secrets/committed-literal', () => {
  it('flags a Stripe live key with masked evidence', () => {
    const finding = findingFor('/a/pay.ts', STRIPE, SECRETS);
    expect(finding?.confidence).toBe('high');
    expect(finding?.evidence).toContain('sk_live_');
    expect(finding?.evidence).not.toContain('FAKEnot'); // the middle is masked
  });

  it('skips test files and the allow pragma', () => {
    expect(idsFor('/a/pay.test.ts', STRIPE, SECRETS)).toHaveLength(0);
    expect(idsFor('/a/ok.ts', `${STRIPE} // aegis-allow-secret`, SECRETS)).toHaveLength(0);
  });
});
