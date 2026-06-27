# @aegiskit/store-upstash

An atomic, **serverless-correct** rate-limit store for [Aegis](https://github.com/your-org/aegis), backed by [Upstash Redis](https://upstash.com).

This is the store that makes Aegis rate limiting correct on serverless: the increment is a single atomic Redis op (a Lua `INCR` + first-hit `PEXPIRE`), so concurrent function invocations share one counter — unlike an in-process map, which resets per instance and never actually limits.

## Install

```bash
pnpm add @aegiskit/store-upstash @upstash/redis
```

## Usage

```ts
import { RateLimiter, RATE_LIMIT_PRESETS } from '@aegiskit/core';
import { createUpstashStore } from '@aegiskit/store-upstash';
import { Redis } from '@upstash/redis';

const limiter = new RateLimiter({
  store: createUpstashStore({ redis: Redis.fromEnv() }),
  failureMode: 'open', // allow on Redis outage (logged); use 'closed' to deny
});

const { success, retryAfter } = await limiter.limit(userId, RATE_LIMIT_PRESETS.auth);
```

Pass the resulting `limiter` to `secure({ rateLimit: { limiter } })` or `secureRoute({ rateLimit: { limiter, rule } })` from `@aegiskit/next`.

## License

MIT
