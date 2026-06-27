import { createMemoryStore, RATE_LIMIT_PRESETS, RateLimiter } from '@aegiskit/core';
import { secureRoute } from '@aegiskit/next';
import { env } from '@/env.server';
import { ingestEvents } from '@/lib/ingest/handler';
import { getEventStore } from '@/lib/store';

const limiter = new RateLimiter({ store: createMemoryStore() });

// NOTE: NO body schema — the HMAC must be verified over the RAW bytes, so the handler reads
// req.text() itself. secureRoute here provides method + rate-limit only (origin auth is the
// signature, not the Origin header → origin: false).
export const POST = secureRoute(
  {
    method: 'POST',
    origin: false,
    rateLimit: { limiter, rule: { ...RATE_LIMIT_PRESETS.api, prefix: 'ingest' } },
  },
  async ({ req }) => {
    const result = await ingestEvents({
      rawBody: await req.text(),
      timestamp: req.headers.get('x-aegis-timestamp'),
      signature: req.headers.get('x-aegis-signature'),
      secret: env.AEGIS_INGEST_SECRET,
      store: getEventStore(),
    });
    return new Response(null, { status: result.status });
  },
);
