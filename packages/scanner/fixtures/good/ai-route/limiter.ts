import { createMemoryStore, RATE_LIMIT_PRESETS, RateLimiter } from '@aegiskit/core';

export const limiter = new RateLimiter({ store: createMemoryStore() });
export const aiRule = RATE_LIMIT_PRESETS.ai;
