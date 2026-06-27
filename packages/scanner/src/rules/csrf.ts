import { codeOnlyText } from '../internal/ast';
import { hasAnyToken } from '../internal/patterns';
import { wrapRouteHandlersWithSecureRoute } from '../internal/wrap-route';
import { docsUrlFor, type Rule } from '../rule';

const MUTATING_EXPORTS = ['POST', 'PUT', 'PATCH', 'DELETE'];
const ORIGIN_CHECK_TOKENS = [
  'verifyorigin',
  'sec-fetch-site',
  'verifysameorigin',
  'assertcsrf',
  'secureroute',
  "headers.get('origin')",
  'headers.get("origin")',
];
const COOKIE_AUTH_TOKENS = ['cookies(', '@supabase/ssr', 'createserverclient', "get('cookie')"];
const BEARER_TOKENS = ['authorization', 'bearer ', 'authenticateapikey', 'x-api-key', 'apikey'];

export const missingOriginCheck: Rule = {
  meta: {
    id: 'csrf/missing-origin-check',
    title: 'Cookie-authenticated mutation lacks an Origin/CSRF check',
    severity: 'HIGH',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('csrf/missing-origin-check'),
  },
  appliesTo: (file) => file.classification.isRouteHandler && !file.classification.isServerAction,
  check(ctx) {
    const mutating = MUTATING_EXPORTS.filter((method) =>
      ctx.file.classification.exportedNames.has(method),
    );
    if (mutating.length === 0) {
      return;
    }
    // Match the auth/origin heuristics against CODE only — a comment that merely *names* `@supabase/ssr`
    // or `cookies(` (e.g. a Sentry-tunnel route explaining its import exception) must not be read as
    // evidence the handler is cookie-authenticated.
    const text = codeOnlyText(ctx.file.sourceFile);
    if (!hasAnyToken(text, COOKIE_AUTH_TOKENS)) {
      return; // not cookie-authed → not an ambient-authority CSRF target here
    }
    if (hasAnyToken(text, BEARER_TOKENS)) {
      ctx.pass('Mutating route authenticates via bearer/API key, not ambient cookies.');
      return;
    }
    if (hasAnyToken(text, ORIGIN_CHECK_TOKENS)) {
      ctx.pass('Mutating route performs an Origin/CSRF check.');
      return;
    }
    ctx.report({
      node: ctx.file.sourceFile,
      confidence: 'medium',
      message: `This cookie-authenticated ${mutating.join('/')} route handler performs no Origin/CSRF check — custom Route Handlers (unlike Server Actions) get none by default.`,
      remediation:
        'Wrap the handler with @aegiskit/next `secureRoute` (origin checks default on), or call `verifyOrigin` before mutating state.',
      // Safe only for the canonical `export [async] function METHOD(req)` shape; the codemod
      // returns undefined (→ guided) for dynamic routes, arrow handlers, re-exports, etc.
      fix: () => wrapRouteHandlersWithSecureRoute(ctx.file.sourceFile, mutating),
    });
  },
};
