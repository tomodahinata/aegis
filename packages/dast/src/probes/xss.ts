import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, getOk, pathOf, randomMarker, withQuery } from './helpers';
import type { Probe, ProbeMeta } from './types';

const REFLECT_PARAMS = ['q', 'search', 'query', 'name', 'message', 's', 'term'];

const meta: ProbeMeta = {
  id: 'dast/reflected-xss',
  title: 'Reflected cross-site scripting',
  severity: 'HIGH',
  owasp: 'A03:2021 Injection',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/reflected-xss'),
};

export const reflectedXss: Probe = {
  meta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    const marker = randomMarker();
    // The active HTML-breaking sequence; a finding requires it to survive UNESCAPED in an HTML body.
    const payload = `${marker}"><svg/onload=1>`;
    for (const param of REFLECT_PARAMS) {
      const url = withQuery(ctx.target.url, param, payload);
      const response = await getOk(ctx, url);
      if (!response) {
        continue;
      }
      const contentType = response.contentType ?? '';
      // Reflection inside JSON/text is correctly serialized — the safe case. Only HTML matters.
      if (!contentType.includes('text/html')) {
        continue;
      }
      if (response.body.includes(`${marker}"><svg/onload=1>`)) {
        ctx.report(
          dynamicFinding(meta, ctx, {
            confidence: 'high',
            message: `${ctx.target.path} reflects the "?${param}=" value into the HTML response without escaping — injected markup and script execute in the visitor's session (reflected XSS).`,
            remediation:
              'Escape user input for the HTML context (or render via a framework that auto-escapes); never interpolate raw input into HTML.',
            evidence: `?${param}= reflected unescaped in text/html`,
            target: toHttpExchange('GET', pathOf(url), response),
          }),
        );
        return;
      }
    }
  },
};
