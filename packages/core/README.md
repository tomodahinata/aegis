# @aegiskit/core

Framework-agnostic, **edge-safe** security primitives for [Aegis](https://github.com/your-org/aegis). Pure functions with no `node:` or DOM dependencies — they run identically on Node, the edge runtime, and the browser (Web Crypto only).

Most apps consume these through [`@aegiskit/next`](../next); use `@aegiskit/core` directly for non-Next runtimes or custom integrations.

## What's inside

- **CSP** — `buildCspHeader`, `hardenedCspPolicy`, `generateNonce`. A single serialization point that always injects the nonce and never silently mixes a nonce with `'unsafe-inline'`.
- **Security headers** — `buildSecurityHeaders`, `HARDENED_HEADERS`, `STRICT_HEADERS`.
- **Rate limiting** — `RateLimiter` + a tiny `RateLimitStore` contract (atomicity lives in the store, so the same limiter is correct on serverless). `RATE_LIMIT_PRESETS`, `createMemoryStore` (dev-only).
- **CSRF / origin** — `verifyOrigin` (fail-closed, `Sec-Fetch-Site` aware), double-submit + signed-token helpers.
- **Typed env** — `defineEnv` with compile-time + runtime `NEXT_PUBLIC_` enforcement.
- **Security events** — a discriminated-union `SecurityEvent` + pluggable `SecuritySink`.

```ts
import { hardenedCspPolicy, buildCspHeader, generateNonce } from '@aegiskit/core';

const nonce = generateNonce();
const csp = buildCspHeader(hardenedCspPolicy(), nonce, 'enforce');
// csp.name === 'Content-Security-Policy', csp.value contains `'nonce-…' 'strict-dynamic'`
```

## License

MIT
