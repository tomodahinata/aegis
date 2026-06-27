# @aegiskit/observability

The read/consumer side of Aegis: a pluggable `EventStore`, a deterministic posture score, the canonical severity table, and the ingestion signature verifier. Runs in your dashboard / ingestion service — never on the request hot path.

```ts
import {
  createMemoryEventStore,
  computePostureScore,
  verifyBatchSignature,
} from '@aegiskit/observability';

const store = createMemoryEventStore();            // dev/self-host default; Upstash/Supabase adapters for prod
await store.append(events);                        // idempotent on event id
const summary = await store.summary({ since, until });
const { score, grade } = computePostureScore(summary); // 0–100, A–F — monotonic & deterministic

// On the ingestion endpoint (verify the RAW body, not a re-serialized object):
const ok = await verifyBatchSignature(secret, rawBody, timestamp, signatureHeader);
```

- **`EventStore`** — `append` / `query` (newest-first, filtered) / `summary` (counts, block-rate, time buckets). `createMemoryEventStore` is a single-instance ring buffer; production adapters live in `@aegiskit/store-supabase` (and the Upstash store).
- **`computePostureScore`** — pure, deterministic, **monotonic** (adding any event never raises the score), recency-decayed. `csp_violation` is weighted *low* on purpose (attacker-controllable → can't be used to tank a victim's score).
- **`verifyBatchSignature`** — HMAC-SHA-256 over `timestamp + "." + rawBody`, constant-time (`subtle.verify`), with a replay window. The counterpart to `@aegiskit/core`'s `createHttpSink`.

## License

MIT
