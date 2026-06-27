import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, pathOf } from './helpers';
import type { Probe, ProbeMeta } from './types';

/** A small, gentle burst — enough to detect the absence of any limit without stressing the target. */
const BURST = 10;

const meta: ProbeMeta = {
  id: 'dast/missing-rate-limit',
  title: 'No rate limit observed',
  severity: 'MEDIUM',
  owasp: 'A04:2021 Insecure Design',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/missing-rate-limit'),
};

export const missingRateLimit: Probe = {
  meta,
  appliesTo: (target) => target.methods.has('GET'),
  async run(ctx) {
    let last: Awaited<ReturnType<typeof ctx.http.send>> | undefined;
    for (let i = 0; i < BURST; i += 1) {
      const result = await ctx.http.send({ method: 'GET', url: ctx.target.url });
      if (!result.ok) {
        // Budget/deadline/network: inconclusive — never claim "no limit" without having actually burst.
        return;
      }
      last = result;
      if (result.response.status === 429) {
        return; // a limit exists — correct, no finding
      }
    }
    if (last?.ok) {
      ctx.report(
        dynamicFinding(meta, ctx, {
          confidence: 'medium',
          message: `${ctx.target.path} served ${BURST} rapid requests with no 429 — it shows no sign of rate limiting, leaving it open to brute-force and resource-abuse.`,
          remediation:
            'Apply a rate limit (e.g. @aegiskit/next `secureRoute({ rateLimit })` or middleware) to sensitive and cost-bearing routes.',
          evidence: `${BURST} requests, no 429`,
          target: toHttpExchange('GET', pathOf(ctx.target.url), last.response),
        }),
      );
    }
  },
};
