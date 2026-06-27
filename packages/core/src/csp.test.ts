import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  buildCspHeader,
  type CspKeyword,
  type CspPolicyConfig,
  type CspSource,
  cspHost,
  generateNonce,
  hardenedCspPolicy,
  resolveCspMode,
} from './csp';

const nonce = generateNonce();

function scriptSrcOf(value: string): string {
  const part = value.split('; ').find((p) => p.startsWith('script-src '));
  expect(part).toBeDefined();
  return part as string;
}

describe('generateNonce', () => {
  it('produces a URL-safe, unpadded, ~128-bit token', () => {
    const n = generateNonce();
    expect(n).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(n).not.toContain('=');
  });

  it('is unique across calls', () => {
    const nonces = new Set(Array.from({ length: 1000 }, () => generateNonce()));
    expect(nonces.size).toBe(1000);
  });
});

describe('resolveCspMode', () => {
  it('maps known values and defaults safely to report-only', () => {
    expect(resolveCspMode('enforce')).toBe('enforce');
    expect(resolveCspMode('report-only')).toBe('report-only');
    expect(resolveCspMode('off')).toBe('off');
    expect(resolveCspMode(undefined)).toBe('report-only');
    expect(resolveCspMode('garbage')).toBe('report-only');
    expect(resolveCspMode('garbage', 'enforce')).toBe('enforce');
  });
});

describe('cspHost', () => {
  it('accepts valid hosts and schemes', () => {
    expect(cspHost('https://example.com')).toBe('https://example.com');
    expect(cspHost('*.example.com')).toBe('*.example.com');
    expect(cspHost('data:')).toBe('data:');
    expect(cspHost('*')).toBe('*');
  });

  it('rejects anything that could smuggle a keyword or break the policy', () => {
    expect(() => cspHost("'unsafe-inline'")).toThrow();
    expect(() => cspHost('has space')).toThrow();
    expect(() => cspHost('a;b')).toThrow();
    expect(() => cspHost('')).toThrow();
  });
});

describe('buildCspHeader', () => {
  const policy: CspPolicyConfig = {
    directives: { 'default-src': ["'self'"], 'script-src': ["'self'"] },
  };

  it('returns null when mode is off', () => {
    expect(buildCspHeader(policy, nonce, 'off')).toBeNull();
  });

  it('uses the enforcing header name in enforce mode', () => {
    const built = buildCspHeader(policy, nonce, 'enforce');
    expect(built?.name).toBe('Content-Security-Policy');
  });

  it('uses the report-only header name in report-only mode', () => {
    const built = buildCspHeader(policy, nonce, 'report-only');
    expect(built?.name).toBe('Content-Security-Policy-Report-Only');
  });

  it('always injects the nonce into script-src (single source of truth)', () => {
    const built = buildCspHeader(policy, nonce, 'enforce');
    expect(scriptSrcOf(built?.value ?? '')).toContain(`'nonce-${nonce}'`);
  });

  it('adds strict-dynamic and drops inert host/self sources from script-src', () => {
    const built = buildCspHeader(
      {
        directives: { 'script-src': ["'self'", cspHost('https://cdn.example.com')] },
        strictDynamic: true,
      },
      nonce,
      'enforce',
    );
    const scriptSrc = scriptSrcOf(built?.value ?? '');
    expect(scriptSrc).toContain("'strict-dynamic'");
    expect(scriptSrc).not.toContain('https://cdn.example.com');
    expect(scriptSrc).not.toContain("'self'");
  });

  it('never mixes a nonce with unsafe-inline by default (the B2 footgun)', () => {
    const built = buildCspHeader(
      { directives: { 'script-src': ["'self'", "'unsafe-inline'"] } },
      nonce,
      'enforce',
    );
    expect(scriptSrcOf(built?.value ?? '')).not.toContain("'unsafe-inline'");
  });

  it('re-adds unsafe-inline only when the legacy fallback is explicitly enabled', () => {
    const built = buildCspHeader(
      {
        directives: { 'script-src': ["'self'"] },
        strictDynamic: false,
        legacyUnsafeInlineFallback: true,
      },
      nonce,
      'enforce',
    );
    expect(scriptSrcOf(built?.value ?? '')).toContain("'unsafe-inline'");
  });

  it('serializes boolean and reporting directives', () => {
    const built = buildCspHeader(
      {
        directives: {
          'default-src': ["'self'"],
          'upgrade-insecure-requests': true,
          'report-to': 'aegis',
          'report-uri': '/api/aegis/csp-report',
        },
      },
      nonce,
      'enforce',
    );
    expect(built?.value).toContain('upgrade-insecure-requests');
    expect(built?.value).toContain('report-to aegis');
    expect(built?.value).toContain('report-uri /api/aegis/csp-report');
    expect(built?.reportingEndpoints).toBe('aegis="/api/aegis/csp-report"');
  });

  it('property: under strict-dynamic, script-src has exactly one nonce and never unsafe-inline', () => {
    const keywordArb = fc.constantFrom<CspKeyword>(
      "'self'",
      "'unsafe-inline'",
      "'unsafe-eval'",
      "'strict-dynamic'",
      "'report-sample'",
    );
    const hostArb = fc
      .constantFrom('https://cdn.example.com', '*.example.com', 'https://x.test')
      .map((h): CspSource => cspHost(h));
    const sourceArb: fc.Arbitrary<CspSource> = fc.oneof(keywordArb, hostArb);

    fc.assert(
      fc.property(fc.array(sourceArb, { maxLength: 12 }), (sources) => {
        const built = buildCspHeader(
          { directives: { 'script-src': sources }, strictDynamic: true },
          nonce,
          'enforce',
        );
        const scriptSrc = scriptSrcOf(built?.value ?? '');
        const nonceCount = scriptSrc.split(`'nonce-${nonce}'`).length - 1;
        expect(nonceCount).toBe(1);
        expect(scriptSrc).not.toContain("'unsafe-inline'");
      }),
    );
  });
});

describe('hardenedCspPolicy', () => {
  it('locks down the dangerous directives by default', () => {
    const built = buildCspHeader(hardenedCspPolicy(), nonce, 'enforce');
    const value = built?.value ?? '';
    expect(value).toContain("object-src 'none'");
    expect(value).toContain("base-uri 'none'");
    expect(value).toContain("frame-ancestors 'none'");
    expect(value).toContain('upgrade-insecure-requests');
    expect(scriptSrcOf(value)).toContain("'strict-dynamic'");
  });

  it('threads optional allowlists into the right directives', () => {
    const built = buildCspHeader(
      hardenedCspPolicy({ connect: ['https://api.example.com'], frame: ['https://js.stripe.com'] }),
      nonce,
      'enforce',
    );
    const value = built?.value ?? '';
    expect(value).toContain('connect-src');
    expect(value).toContain('https://api.example.com');
    expect(value).toContain('https://js.stripe.com');
  });
});
