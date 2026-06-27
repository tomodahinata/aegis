import { authRequired, idor } from './authz';
import { cookieFlags, securityHeaders } from './headers';
import { errorDisclosure } from './misconfig';
import { missingRateLimit } from './ratelimit';
import { openRedirect } from './redirect';
import { sqlInjection } from './sqli';
import { ssrf } from './ssrf';
import type { Probe } from './types';
import { reflectedXss } from './xss';

/** The built-in probe set. Passive probes run by default; `active` probes need `mode: 'active'`. */
export const ALL_PROBES: readonly Probe[] = [
  // Passive / non-mutating (run by default).
  securityHeaders,
  cookieFlags,
  errorDisclosure,
  openRedirect,
  reflectedXss,
  sqlInjection,
  ssrf,
  missingRateLimit,
  // Active — credentialed authorization probes (only with mode: 'active').
  authRequired,
  idor,
];

export {
  authRequired,
  cookieFlags,
  errorDisclosure,
  idor,
  missingRateLimit,
  openRedirect,
  reflectedXss,
  securityHeaders,
  sqlInjection,
  ssrf,
};
