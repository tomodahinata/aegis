import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, getOk, pathOf, withQuery } from './helpers';
import type { Probe, ProbeMeta } from './types';

const SSRF_PARAMS = ['url', 'uri', 'callback', 'webhook', 'target'];

const meta: ProbeMeta = {
  id: 'dast/ssrf',
  title: 'Server-side request forgery (runtime-confirmed)',
  severity: 'HIGH',
  owasp: 'A10:2021 Server-Side Request Forgery',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/ssrf'),
};

export const ssrf: Probe = {
  meta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    // One token across all candidate params → a single out-of-band wait (fast, and zero false
    // positives: only an actual callback confirms egress).
    const canary = ctx.canary.issue();
    let lastResponse: Awaited<ReturnType<typeof getOk>>;
    let lastUrl = ctx.target.url;
    for (const param of SSRF_PARAMS) {
      const url = withQuery(ctx.target.url, param, canary.url);
      const response = await getOk(ctx, url);
      if (response) {
        lastResponse = response;
        lastUrl = url;
      }
    }
    if (!lastResponse) {
      return;
    }
    if (await ctx.canary.awaitHit(canary.token, 1000)) {
      ctx.report(
        dynamicFinding(meta, ctx, {
          confidence: 'high',
          message: `${ctx.target.path} fetched an attacker-supplied URL server-side — confirmed by an out-of-band callback. An attacker can reach internal services or cloud metadata (SSRF).`,
          remediation:
            'Resolve the input against a fixed trusted base, or validate the host against an allowlist before fetching. Never fetch a fully attacker-controlled URL.',
          evidence: 'a URL parameter triggered a server-side fetch to the canary',
          target: toHttpExchange('GET', pathOf(lastUrl), lastResponse),
        }),
      );
    }
  },
};
