/**
 * `@aegiskit/next` — Next.js (App Router) security adapters over `@aegiskit/core`.
 *
 * The server-only env boundary is exported separately from `@aegiskit/next/env` so this main
 * entry never imports `server-only` (and can be used from `middleware.ts`/`proxy.ts`).
 */

export { NONCE_HEADER } from './constants';
export { type CspReportHandlerOptions, createCspReportHandler } from './csp-report';
export { getNonce } from './nonce';
export {
  type AegisMiddleware,
  type SecureChainContext,
  type SecureConfig,
  type SecureRateLimitConfig,
  secure,
} from './secure';
export {
  type HttpMethod,
  type RouteContext,
  type RouteRateLimitConfig,
  type RouteSchemas,
  secureRoute,
  type ValidatedInput,
  withValidation,
} from './secure-route';
