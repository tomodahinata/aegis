/**
 * `@aegiskit/observability` — the read/consumer side of Aegis: a pluggable `EventStore`, a
 * deterministic posture score, the canonical severity table, and the ingestion signature
 * verifier. Runs in the dashboard / ingestion service (not the request hot path).
 */

export { computePostureScore, type Grade, type PostureScore } from './posture';
export { EVENT_SEVERITY, SEVERITY_WEIGHT, type Severity } from './severity';
export { type VerifyOptions, verifyBatchSignature } from './signature';
export {
  createMemoryEventStore,
  type EventQuery,
  type EventStore,
  type MemoryEventStoreOptions,
  type PostureBucket,
  type PostureSummary,
  type StoredEvent,
  type SummaryWindow,
  summarize,
} from './store';
