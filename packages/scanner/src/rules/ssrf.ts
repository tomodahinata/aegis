import { ts } from '../internal/ast';
import type { TaintSink } from '../internal/taint-descriptors';
import { looksRelativeUrl } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

const HTTP_FUNCS: ReadonlySet<string> = new Set(['fetch', 'axios', 'got', 'ky']);
const HTTP_METHODS: ReadonlySet<string> = new Set([
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'request',
  'head',
]);

/** The URL argument of a server-side HTTP call, unless it is a same-origin relative path (not SSRF). */
const fetchSink: TaintSink = {
  id: 'ssrf.fetch',
  category: 'url',
  label: 'reaches a server-side fetch',
  match: (node) => {
    if (!ts.isCallExpression(node)) {
      return [];
    }
    const callee = node.expression;
    let url: ts.Expression | undefined;
    if (ts.isIdentifier(callee) && HTTP_FUNCS.has(callee.text)) {
      url = node.arguments[0];
    } else if (
      ts.isPropertyAccessExpression(callee) &&
      HTTP_METHODS.has(callee.name.text) &&
      /\b(?:axios|got|ky|https?)\b/.test(callee.expression.getText())
    ) {
      url = node.arguments[0];
    }
    return url && !looksRelativeUrl(url) ? [url] : [];
  },
};

export const ssrf = defineTaintRule({
  meta: {
    id: 'ssrf/tainted-fetch',
    title: 'Server-side request to an untrusted URL (SSRF)',
    severity: 'HIGH',
    owasp: 'A10:2021 Server-Side Request Forgery',
    docsUrl: docsUrlFor('ssrf/tainted-fetch'),
  },
  // Server/edge only: a client-side fetch to a tainted same-origin path is not SSRF.
  appliesTo: (file) =>
    file.classification.context !== 'client' && /\b(?:fetch|axios|got|ky)\b/.test(file.text),
  spec: { sinks: [fetchSink] },
  message:
    'A server-side HTTP request targets a URL built from untrusted input — an attacker can pivot to internal services or cloud metadata (SSRF).',
  remediation:
    'Resolve the input against a fixed, trusted base (new URL(path, BASE)) or check it against an allowlist of permitted hosts before fetching. Never fetch a fully attacker-controlled URL.',
  passDetail: 'A server-side fetch URL is pinned to a trusted host before use.',
});
