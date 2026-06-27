import { ts } from '../internal/ast';
import type { TaintSink } from '../internal/taint-descriptors';
import { looksRelativeUrl } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

const REDIRECTORS: ReadonlySet<string> = new Set(['redirect']);

/** A `redirect(target)` / `NextResponse.redirect(target)` whose target is not a same-site relative path. */
const redirectSink: TaintSink = {
  id: 'redirect.target',
  category: 'url',
  label: 'reaches a redirect',
  match: (node) => {
    if (!ts.isCallExpression(node)) {
      return [];
    }
    const callee = node.expression;
    const isRedirect =
      (ts.isIdentifier(callee) && REDIRECTORS.has(callee.text)) ||
      (ts.isPropertyAccessExpression(callee) && callee.name.text === 'redirect');
    if (!isRedirect) {
      return [];
    }
    const target = node.arguments[0];
    return target && !looksRelativeUrl(target) ? [target] : [];
  },
};

export const openRedirect = defineTaintRule({
  meta: {
    id: 'redirect/open-redirect',
    title: 'Redirect to an untrusted target',
    severity: 'MEDIUM',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('redirect/open-redirect'),
  },
  appliesTo: (file) => /\bredirect\s*\(/.test(file.text),
  spec: { sinks: [redirectSink] },
  // A relative redirect is a common, safe pattern that is hard to prove away syntactically, so this
  // rule informs rather than blocks CI.
  maxConfidence: 'medium',
  message:
    'A redirect target is built from untrusted input — an attacker can craft a link that bounces users to a phishing site (open redirect).',
  remediation:
    'Redirect only to a relative path, or validate the target against an allowlist of permitted destinations. Resolve external input with new URL(target, ORIGIN) and check the host.',
  passDetail: 'A redirect target derived from input is pinned to a trusted host.',
});
