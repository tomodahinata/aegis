/**
 * `@aegiskit/core` — framework-agnostic, edge-safe security primitives.
 *
 * Pure functions and small classes with no `node:`/DOM dependencies, so they run identically
 * on Node, the edge runtime, and the browser. Framework glue lives in adapter packages
 * (`@aegiskit/next`). Internal helpers under `./internal` are intentionally not re-exported.
 */

export * from './csp';
export * from './csrf';
export * from './env';
export * from './events';
export * from './headers';
export * from './http-sink';
export * from './rate-limit';
