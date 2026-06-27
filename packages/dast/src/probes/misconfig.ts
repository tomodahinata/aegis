import { toHttpExchange } from '../http/evidence';
import { docsUrlFor, dynamicFinding, getOk, pathOf, withQuery } from './helpers';
import type { Probe, ProbeMeta } from './types';

// Note: TRACE/XST detection is intentionally omitted — the Fetch standard forbids the TRACE method, so
// it cannot be sent through the safety-gated HTTP client. Detecting it would require a raw socket that
// bypasses the kernel, which we refuse to do. (A future raw-socket probe could add it.)

// Markers that a response leaked an internal stack trace / framework error / DB driver error.
const STACK_MARKERS =
  /\bat\s+\S+\s+\(.*:\d+:\d+\)|node_modules|webpack-internal|\bPostgresError\b|SQLSTATE|\.ts:\d+:\d+|TypeError:|ReferenceError:|\bECONNREFUSED\b/;

const errorMeta: ProbeMeta = {
  id: 'dast/error-disclosure',
  title: 'Server leaks an internal stack trace / error detail',
  severity: 'MEDIUM',
  owasp: 'A05:2021 Security Misconfiguration',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/error-disclosure'),
};

export const errorDisclosure: Probe = {
  meta: errorMeta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    // A deliberately odd value that often trips un-guarded parsing/coercion.
    const url = withQuery(ctx.target.url, 'aegisProbe', `'"><[]{}`);
    const response = await getOk(ctx, url);
    if (!response) {
      return;
    }
    const match = STACK_MARKERS.exec(response.body);
    if (match) {
      ctx.report(
        dynamicFinding(errorMeta, ctx, {
          confidence: 'medium',
          message: `${ctx.target.path} returned an internal stack trace / framework error in the response body — it discloses file paths, dependencies, or query internals to an attacker.`,
          remediation:
            'Return a generic error to clients and log details server-side. Ensure production builds do not ship the dev error overlay.',
          evidence: `leaked: ${match[0].slice(0, 48)}`,
          target: toHttpExchange('GET', pathOf(url), response),
        }),
      );
    }
  },
};
