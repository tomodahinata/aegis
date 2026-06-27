import { calleeName, collectCalls } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';

const SUPABASE_CONSTRUCTORS = new Set([
  'createClient',
  'createServerClient',
  'createAdminClient',
  'createBrowserClient',
]);

export const serviceRoleOutsideAdmin: Rule = {
  meta: {
    id: 'supabase/service-role-outside-admin',
    title: 'Supabase service_role key reachable from the client/edge',
    severity: 'BLOCKER',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('supabase/service-role-outside-admin'),
  },
  appliesTo: (file) =>
    /SERVICE_ROLE/i.test(file.text) &&
    (file.classification.context === 'client' ||
      file.classification.context === 'edge' ||
      file.reachableFromClient),
  check(ctx) {
    for (const call of collectCalls(ctx.file.sourceFile)) {
      const name = calleeName(call);
      if (name === undefined || !SUPABASE_CONSTRUCTORS.has(name)) {
        continue;
      }
      const argsText = call.arguments.map((arg) => arg.getText(ctx.file.sourceFile)).join(' ');
      if (/SERVICE_ROLE/i.test(argsText)) {
        ctx.report({
          node: call,
          confidence: 'high',
          message:
            'A Supabase client is built with the SERVICE_ROLE key in client/edge/client-reachable code. The service role bypasses Row Level Security — if it reaches the browser or an un-gated path, it is a full data breach.',
          remediation:
            'Construct the service-role client only in server-only modules behind an authorization gate; never import it from a Client Component or an unauthenticated route.',
          evidence: `${name}(… SERVICE_ROLE …)`,
        });
      }
    }
  },
};
