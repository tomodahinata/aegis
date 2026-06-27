import { secureRoute } from '@aegiskit/next';
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';
import { limiter, aiRule } from './limiter';

// AI route IS rate-limited via secureRoute — no finding.
export const POST = secureRoute(
  { method: 'POST', rateLimit: { limiter, rule: aiRule } },
  async () => streamText({ model: openai('gpt-4o'), prompt: 'hi' }).toTextStreamResponse(),
);
