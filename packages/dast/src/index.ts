/**
 * `@aegiskit/dast` — dynamic application security testing for Aegis.
 *
 * Sends safe, bounded, NON-DESTRUCTIVE HTTP probes to a running app you OWN and are authorized to test,
 * confirms a subset of vulnerabilities at runtime, and correlates them with `@aegiskit/scanner`'s static
 * findings — turning a static "possible injection" into a runtime-confirmed, build-blocking one.
 *
 * It is not exhaustive and does not "run every attack". It defaults to localhost; any other host needs
 * explicit, attested consent. It complements — never replaces — static analysis, code review, and
 * manual penetration testing.
 */

export { type CorrelatedResult, type Correlation, correlate } from './correlate';
export {
  type PlannedRequest,
  type ProbeMode,
  type ProbeOptions,
  type ProbeResult,
  probe,
} from './engine';
export { ALL_PROBES } from './probes/registry';
export type {
  BlastRadius,
  DynamicFinding,
  Identity,
  IdentityAuth,
  IdentityConfig,
  Probe,
  ProbeContext,
  ProbeMeta,
  Target,
} from './probes/types';
export { toFinding, toScanResult } from './report';
export { type Budget, DEFAULT_BUDGET, resolveBudget } from './safety/budget';
export { type AuthorizationAck, type RemoteConsent, ScopeError } from './safety/consent';
