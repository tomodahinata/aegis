import { collectProcessEnvKeys, looksSecret } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';

export const publicSecret: Rule = {
  meta: {
    id: 'env/public-secret',
    title: 'Secret exposed via NEXT_PUBLIC_ prefix',
    severity: 'BLOCKER',
    owasp: 'A05:2021 Security Misconfiguration',
    docsUrl: docsUrlFor('env/public-secret'),
  },
  appliesTo: (file) => file.text.includes('NEXT_PUBLIC_'),
  check(ctx) {
    for (const env of collectProcessEnvKeys(ctx.file.sourceFile)) {
      if (env.key.startsWith('NEXT_PUBLIC_') && looksSecret(env.key)) {
        ctx.report({
          node: env.node,
          confidence: 'high',
          message: `\`${env.key}\` is exposed to the browser by the NEXT_PUBLIC_ prefix, but its name denotes a secret — anything NEXT_PUBLIC_ is inlined into the client bundle.`,
          remediation:
            'Drop the NEXT_PUBLIC_ prefix and read it only on the server (e.g. @aegiskit/next/env `defineServerEnv`); expose only genuinely public values.',
          evidence: env.key,
        });
      }
    }
  },
};

export const secretInClient: Rule = {
  meta: {
    id: 'env/secret-in-client',
    title: 'Server secret read in client-reachable code',
    severity: 'BLOCKER',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('env/secret-in-client'),
  },
  appliesTo: (file) =>
    (file.classification.context === 'client' || file.reachableFromClient) &&
    file.text.includes('process.env'),
  check(ctx) {
    for (const env of collectProcessEnvKeys(ctx.file.sourceFile)) {
      if (!env.key.startsWith('NEXT_PUBLIC_') && looksSecret(env.key)) {
        ctx.report({
          node: env.node,
          confidence: 'high',
          message: `Secret env var \`${env.key}\` is read in client-reachable code; server secrets must never be referenced where a bundler can include them in the browser build.`,
          remediation:
            'Move this read into a server-only module (e.g. behind @aegiskit/next/env `defineServerEnv`) and pass only non-secret data to the client.',
          evidence: env.key,
        });
      }
    }
  },
};
