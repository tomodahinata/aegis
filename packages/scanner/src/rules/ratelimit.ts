import type { ts } from '../internal/ast';
import { calleeName, collectCalls, hasAnyToken, importsFrom } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';

const LLM_MODULES = [/^openai$/, /^@anthropic-ai\//, /^@ai-sdk\//, /^ai$/];
const LLM_CALL_NAMES = new Set([
  'streamText',
  'generateText',
  'generateObject',
  'streamObject',
  'createCompletion',
  'createChatCompletion',
]);
const RATE_LIMIT_TOKENS = ['ratelimit', '.limit(', 'checkratelimit', 'secureroute'];

function findLlmCall(sourceFile: ts.SourceFile): ts.Node | undefined {
  return collectCalls(sourceFile).find((call) => {
    const name = calleeName(call);
    return name !== undefined && LLM_CALL_NAMES.has(name);
  });
}

export const missingRateLimitOnAi: Rule = {
  meta: {
    id: 'ratelimit/missing-on-ai-route',
    title: 'AI/LLM route has no rate limit',
    severity: 'HIGH',
    owasp: 'A04:2021 Insecure Design',
    docsUrl: docsUrlFor('ratelimit/missing-on-ai-route'),
  },
  appliesTo: (file) => file.classification.isRouteHandler,
  check(ctx) {
    const llmCall = findLlmCall(ctx.file.sourceFile);
    const usesLlm = importsFrom(ctx.file, LLM_MODULES) || llmCall !== undefined;
    if (!usesLlm) {
      return;
    }
    if (hasAnyToken(ctx.file.text, RATE_LIMIT_TOKENS)) {
      ctx.pass('AI route applies a rate limit.');
      return;
    }
    ctx.report({
      node: llmCall ?? ctx.file.sourceFile,
      confidence: 'high',
      message:
        'This route invokes an LLM/AI SDK with no rate limit — an attacker can drive unbounded token usage (and cost).',
      remediation:
        'Wrap the handler with @aegiskit/next `secureRoute({ rateLimit: { limiter, rule: RATE_LIMIT_PRESETS.ai } })`, or call a limiter before the model request.',
    });
  },
};
