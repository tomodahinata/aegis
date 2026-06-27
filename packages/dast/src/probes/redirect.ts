import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, getOk, pathOf, withQuery } from './helpers';
import type { Probe, ProbeMeta } from './types';

// A host we never fetch — we only read whether the app reflects it into a redirect Location.
const SENTINEL_HOST = 'aegis-redirect-canary.example';
const REDIRECT_PARAMS = ['next', 'redirect', 'url', 'returnTo', 'dest', 'continue'];

const meta: ProbeMeta = {
  id: 'dast/open-redirect',
  title: 'Open redirect to an attacker-controlled host',
  severity: 'MEDIUM',
  owasp: 'A01:2021 Broken Access Control',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/open-redirect'),
};

export const openRedirect: Probe = {
  meta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    for (const param of REDIRECT_PARAMS) {
      const url = withQuery(ctx.target.url, param, `https://${SENTINEL_HOST}/x`);
      const response = await getOk(ctx, url);
      if (!response?.location) {
        continue;
      }
      let host: string;
      try {
        host = new URL(response.location, ctx.origin).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (host === SENTINEL_HOST) {
        ctx.report(
          dynamicFinding(meta, ctx, {
            confidence: 'high',
            message: `${ctx.target.path} redirects to a fully attacker-controlled host via "?${param}=" — a crafted link bounces users to a phishing site (open redirect).`,
            remediation:
              'Redirect only to a relative path, or validate the target against an allowlist of permitted destinations.',
            evidence: `?${param}= → Location ${SENTINEL_HOST}`,
            target: toHttpExchange('GET', pathOf(url), response),
          }),
        );
        return; // one finding per route is enough
      }
    }
  },
};
