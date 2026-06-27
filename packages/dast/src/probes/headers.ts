import type { Severity } from '@aegiskit/scanner';
import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, getOk, pathOf } from './helpers';
import type { Probe, ProbeMeta } from './types';

// (label, header, severity-when-missing). Generalizes the doctor command's LIVE_HEADER_CHECKS.
const REQUIRED_HEADERS: ReadonlyArray<readonly [string, string, Severity]> = [
  ['Content-Security-Policy', 'content-security-policy', 'HIGH'],
  ['Strict-Transport-Security', 'strict-transport-security', 'HIGH'],
  ['X-Content-Type-Options', 'x-content-type-options', 'MEDIUM'],
  ['X-Frame-Options', 'x-frame-options', 'MEDIUM'],
  ['Referrer-Policy', 'referrer-policy', 'LOW'],
];

const headersMeta: ProbeMeta = {
  id: 'dast/security-headers',
  title: 'Security response header missing at runtime',
  severity: 'HIGH',
  owasp: 'A05:2021 Security Misconfiguration',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/security-headers'),
};

export const securityHeaders: Probe = {
  meta: headersMeta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    const response = await getOk(ctx, ctx.target.url);
    if (!response) {
      return;
    }
    for (const [label, header, severity] of REQUIRED_HEADERS) {
      // HSTS is correctly absent over plain-http localhost (no TLS) — never a finding there.
      if (header === 'strict-transport-security' && ctx.origin.startsWith('http://')) {
        continue;
      }
      const present =
        response.headers.has(header) ||
        (header === 'content-security-policy' &&
          response.headers.has('content-security-policy-report-only'));
      if (!present) {
        ctx.report(
          dynamicFinding(headersMeta, ctx, {
            severity,
            confidence: 'high',
            message: `${label} is not set on ${ctx.target.path} — the browser protection it provides is absent at runtime.`,
            remediation: `Emit ${label} on every response via middleware (e.g. @aegiskit/next \`secure()\`).`,
            evidence: `missing: ${header}`,
            target: toHttpExchange('GET', pathOf(ctx.target.url), response),
          }),
        );
      }
    }
  },
};

const cookieMeta: ProbeMeta = {
  id: 'dast/cookie-flags',
  title: 'Session cookie missing a security flag',
  severity: 'MEDIUM',
  owasp: 'A05:2021 Security Misconfiguration',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/cookie-flags'),
};

const SESSION_COOKIE = /sess|sid|auth|token|csrf/;

export const cookieFlags: Probe = {
  meta: cookieMeta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    const response = await getOk(ctx, ctx.target.url);
    if (!response) {
      return;
    }
    for (const cookie of response.setCookies) {
      const name = (cookie.split('=')[0] ?? '').trim().toLowerCase();
      if (!SESSION_COOKIE.test(name)) {
        continue;
      }
      const lower = cookie.toLowerCase();
      const missing: string[] = [];
      if (!lower.includes('httponly')) {
        missing.push('HttpOnly');
      }
      if (ctx.origin.startsWith('https://') && !lower.includes('secure')) {
        missing.push('Secure');
      }
      if (!lower.includes('samesite')) {
        missing.push('SameSite');
      }
      if (missing.length > 0) {
        ctx.report(
          dynamicFinding(cookieMeta, ctx, {
            confidence: 'high',
            message: `The session cookie "${name}" is set without ${missing.join(', ')} — it is exposed to theft via XSS or sent on cross-site requests.`,
            remediation:
              'Set HttpOnly, Secure (over HTTPS), and SameSite=Lax|Strict on every session/auth cookie.',
            evidence: `cookie ${name} missing ${missing.join('+')}`,
            target: toHttpExchange('GET', pathOf(ctx.target.url), response),
          }),
        );
      }
    }
  },
};
