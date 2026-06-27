import { describe, expect, it } from 'vitest';
import {
  buildSecurityHeaders,
  HARDENED_HEADERS,
  type SecurityHeadersConfig,
  STRICT_HEADERS,
} from './headers';

function toMap(config: SecurityHeadersConfig): Map<string, string> {
  return new Map(buildSecurityHeaders(config).map(([k, v]) => [k, v]));
}

describe('buildSecurityHeaders', () => {
  it('emits the full hardened set', () => {
    const headers = toMap(HARDENED_HEADERS);
    expect(headers.get('Strict-Transport-Security')).toBe('max-age=63072000; includeSubDomains');
    expect(headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    expect(headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(headers.has('Cross-Origin-Embedder-Policy')).toBe(false); // off by default
  });

  it('serializes a deny-all Permissions-Policy as `feature=()`', () => {
    const value = toMap(HARDENED_HEADERS).get('Permissions-Policy') ?? '';
    expect(value).toContain('camera=()');
    expect(value).toContain('geolocation=()');
  });

  it('quotes origins but leaves self/* bare in Permissions-Policy', () => {
    const value =
      toMap({ permissionsPolicy: { geolocation: ['self', 'https://maps.example.com'] } }).get(
        'Permissions-Policy',
      ) ?? '';
    expect(value).toBe('geolocation=(self "https://maps.example.com")');
  });

  it('omits a header when its value is false', () => {
    const headers = toMap({ hsts: false, frameOptions: false, contentTypeOptions: false });
    expect(headers.has('Strict-Transport-Security')).toBe(false);
    expect(headers.has('X-Frame-Options')).toBe(false);
    expect(headers.has('X-Content-Type-Options')).toBe(false);
  });

  it('enables COEP and preload in the strict preset', () => {
    const headers = toMap(STRICT_HEADERS);
    expect(headers.get('Cross-Origin-Embedder-Policy')).toBe('require-corp');
    expect(headers.get('Strict-Transport-Security')).toContain('preload');
    expect(headers.get('X-Frame-Options')).toBe('DENY');
  });

  it('rejects an HSTS preload without includeSubDomains (fail-fast on misconfig)', () => {
    expect(() => buildSecurityHeaders({ hsts: { maxAge: 63_072_000, preload: true } })).toThrow();
  });

  it('rejects an HSTS preload with too-short max-age', () => {
    expect(() =>
      buildSecurityHeaders({ hsts: { maxAge: 100, includeSubDomains: true, preload: true } }),
    ).toThrow();
  });
});
