import type { Rule } from '../rule';
import { idorTaintedScope, missingAccessFilter } from './authz';
import { codeInjection } from './code-injection';
import { commandInjection } from './command-injection';
import { insecureRandomness, nonConstantTimeCompare, weakHash } from './crypto';
import { cspNonceMintedUnused, cspUnsafeInline } from './csp';
import { missingOriginCheck } from './csrf';
import { domXss } from './dom-xss';
import { publicSecret, secretInClient } from './env';
import { missingSecurityHeaders } from './headers';
import { openRedirect } from './open-redirect';
import { pathTraversal } from './path-traversal';
import { missingRateLimitOnAi } from './ratelimit';
import { committedSecretLiteral } from './secrets';
import { sqlInjection } from './sql-injection';
import { ssrf } from './ssrf';
import { serviceRoleOutsideAdmin } from './supabase';
import { dangerousHtmlUnsanitized } from './xss';

/** The built-in rule set (evidence-grounded, false-positive-gated). */
export const ALL_RULES: readonly Rule[] = [
  // Configuration & secrets (syntactic).
  cspUnsafeInline,
  cspNonceMintedUnused,
  missingSecurityHeaders,
  missingRateLimitOnAi,
  publicSecret,
  secretInClient,
  serviceRoleOutsideAdmin,
  missingOriginCheck,
  dangerousHtmlUnsanitized,
  committedSecretLiteral,
  // Injection family (dataflow / taint).
  sqlInjection,
  ssrf,
  domXss,
  pathTraversal,
  commandInjection,
  openRedirect,
  codeInjection,
  // Cryptographic weaknesses (syntactic).
  insecureRandomness,
  weakHash,
  nonConstantTimeCompare,
  // Authorization: a heuristic "no visible check" prompt (medium) + a proven request-scoped IDOR (high).
  missingAccessFilter,
  idorTaintedScope,
];

export {
  codeInjection,
  commandInjection,
  committedSecretLiteral,
  cspNonceMintedUnused,
  cspUnsafeInline,
  dangerousHtmlUnsanitized,
  domXss,
  idorTaintedScope,
  insecureRandomness,
  missingAccessFilter,
  missingOriginCheck,
  missingRateLimitOnAi,
  missingSecurityHeaders,
  nonConstantTimeCompare,
  openRedirect,
  pathTraversal,
  publicSecret,
  secretInClient,
  serviceRoleOutsideAdmin,
  sqlInjection,
  ssrf,
  weakHash,
};
