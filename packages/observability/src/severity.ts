import type { SecurityEventType } from '@aegiskit/core';

export type Severity = 'low' | 'medium' | 'high';

/**
 * The single authoritative mapping from event type → severity (DRY: consumed by `summarize`
 * and the posture score). `csp_violation` is deliberately **low**: its source is attacker-
 * controllable report bodies, so it must not be a lever to tank a victim's posture score.
 */
export const EVENT_SEVERITY: Readonly<Record<SecurityEventType, Severity>> = {
  origin_block: 'high',
  csrf_block: 'high',
  suspicious_request: 'high',
  rate_limit_block: 'medium',
  validation_error: 'low',
  csp_violation: 'low',
};

export const SEVERITY_WEIGHT: Readonly<Record<Severity, number>> = { high: 10, medium: 3, low: 1 };
