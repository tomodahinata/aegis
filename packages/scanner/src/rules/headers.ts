import type { FileInfo } from '../rule';
import { docsUrlFor, type Rule } from '../rule';

// Case-insensitive over the raw text — no per-file lowercased copy allocated.
const SECURITY_HEADER_RE =
  /content-security-policy|x-frame-options|strict-transport-security|x-content-type-options/i;

/** Does ANY file in the project emit security headers (config, middleware, or via `secure()`)? */
function projectEmitsSecurityHeaders(files: ReadonlyMap<string, FileInfo>): boolean {
  for (const info of files.values()) {
    if (SECURITY_HEADER_RE.test(info.text)) {
      return true;
    }
    if (/@aegis\/next/.test(info.text) && /\bsecure\s*\(/.test(info.text)) {
      return true;
    }
  }
  return false;
}

export const missingSecurityHeaders: Rule = {
  meta: {
    id: 'headers/missing-security-headers',
    title: 'No security headers emitted',
    severity: 'HIGH',
    owasp: 'A05:2021 Security Misconfiguration',
    docsUrl: docsUrlFor('headers/missing-security-headers'),
  },
  appliesTo: (file) => file.classification.isConfig,
  check(ctx) {
    if (projectEmitsSecurityHeaders(ctx.files)) {
      ctx.pass('Security headers are emitted (config, middleware, or `secure()`).');
      return;
    }
    ctx.report({
      node: ctx.file.sourceFile,
      confidence: 'medium',
      message:
        'This project emits no security headers — no CSP, X-Frame-Options, HSTS, or nosniff in next.config or middleware.',
      remediation:
        'Add `secure()` from @aegiskit/next to your middleware/proxy (or run `aegis init`) to apply hardened headers + CSP.',
    });
  },
};
