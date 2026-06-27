import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';

export async function POST(req: Request) {
  const { prompt } = await req.json();
  // No rate limit: an attacker can call this in a loop and run up unbounded model cost.
  const result = streamText({ model: openai('gpt-4o'), prompt });
  return result.toTextStreamResponse();
}
