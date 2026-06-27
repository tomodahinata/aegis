import {
  createConsoleSink,
  createMemoryStore,
  RATE_LIMIT_PRESETS,
  RateLimiter,
} from '@aegiskit/core';
import { secure } from '@aegiskit/next';

// In production use `@aegiskit/store-upstash` instead of the in-memory store (which does not
// hold under serverless concurrency).
const limiter = new RateLimiter({ store: createMemoryStore() });

export default secure({
  sink: createConsoleSink(),
  rateLimit: {
    limiter,
    rule: RATE_LIMIT_PRESETS.ip,
    match: (req) => req.nextUrl.pathname.startsWith('/api'),
  },
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
