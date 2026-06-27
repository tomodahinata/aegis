import type { SecurityEventType } from '@aegiskit/core';
import type { StoredEvent } from '@aegiskit/observability';

/** Build a fully-typed StoredEvent for tests (mirrors the per-variant shape in the store's own tests). */
export function mkEvent(type: SecurityEventType, receivedAt = 1, id: string = type): StoredEvent {
  const base = { at: receivedAt, receivedAt, id };
  switch (type) {
    case 'csrf_block':
      return { ...base, type, reason: 'r' };
    case 'origin_block':
      return { ...base, type, origin: null, reason: 'r' };
    case 'csp_violation':
      return { ...base, type, directive: 'script-src', blockedUri: 'u' };
    case 'validation_error':
      return { ...base, type, issues: [] };
    case 'suspicious_request':
      return { ...base, type, signal: 's' };
    default:
      return { ...base, type: 'rate_limit_block', key: 'k', rule: 'ip', limit: 60 };
  }
}
