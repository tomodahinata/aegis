import { describe, expect, it } from 'vitest';
import { deriveRoutePath, fillParams } from './route-path';

describe('deriveRoutePath', () => {
  it('maps a route file to its URL path', () => {
    expect(deriveRoutePath('/proj/src/app/api/users/route.ts')).toBe('/api/users');
  });
  it('keeps dynamic segments as a pattern', () => {
    expect(deriveRoutePath('/proj/app/api/users/[id]/route.ts')).toBe('/api/users/[id]');
  });
  it('drops route groups', () => {
    expect(deriveRoutePath('/proj/app/(marketing)/pricing/route.ts')).toBe('/pricing');
  });
  it('maps the app root route to /', () => {
    expect(deriveRoutePath('/proj/app/route.ts')).toBe('/');
  });
  it('returns undefined for a non-route file', () => {
    expect(deriveRoutePath('/proj/src/lib/util.ts')).toBeUndefined();
  });
});

describe('fillParams', () => {
  it('fills a dynamic segment', () => {
    expect(fillParams('/api/users/[id]')).toBe('/api/users/1');
  });
  it('fills catch-all and optional catch-all segments', () => {
    expect(fillParams('/api/[...slug]')).toBe('/api/1');
    expect(fillParams('/api/[[...slug]]')).toBe('/api/1');
  });
  it('leaves a static path unchanged', () => {
    expect(fillParams('/api/health')).toBe('/api/health');
  });
});
