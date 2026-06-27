/**
 * `@aegiskit/eslint-config` — an ESLint flat-config preset that catches a few high-confidence
 * Aegis security mistakes at edit time, complementing the (more precise) `aegis scan`.
 *
 * Implemented purely with core ESLint's `no-restricted-syntax` (no plugins, no custom rules),
 * and tuned to be **false-positive-free**: every selector matches only unambiguous problems.
 *
 * Usage (eslint.config.js):
 *   import aegis from '@aegiskit/eslint-config';
 *   export default [ ...aegis ];
 */

/** Minimal flat-config shape (avoids a hard dependency on ESLint's types in this package). */
export interface FlatConfig {
  readonly name?: string;
  readonly files?: readonly string[];
  readonly rules?: Readonly<Record<string, unknown>>;
}

// A NEXT_PUBLIC_-prefixed var whose name denotes a secret → inlined into the client bundle.
const PUBLIC_SECRET =
  "MemberExpression[object.object.name='process'][object.property.name='env'][property.name=/^NEXT_PUBLIC_.*(SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|WEBHOOK_SECRET)/]";

// A hard-coded provider secret (known prefixes only — unambiguous, no entropy guessing).
const COMMITTED_SECRET = 'Literal[value=/^(sk_live_|sk_test_|rk_live_|AKIA[0-9A-Z]{16}|ghp_)/]';

export const aegisSecurityRules: Readonly<Record<string, unknown>> = {
  'no-restricted-syntax': [
    'error',
    {
      selector: PUBLIC_SECRET,
      message:
        'Aegis: a NEXT_PUBLIC_-prefixed secret is exposed to the browser. Drop the prefix and read it server-side (defineServerEnv).',
    },
    {
      selector: COMMITTED_SECRET,
      message:
        'Aegis: a provider secret looks hard-coded. Move it to an env var and rotate the exposed credential.',
    },
    {
      selector: "CallExpression[callee.name='eval']",
      message: 'Aegis: eval() executes arbitrary code (XSS/RCE). Remove it.',
    },
    {
      selector: "NewExpression[callee.name='Function']",
      message: 'Aegis: new Function() executes arbitrary code (XSS/RCE). Remove it.',
    },
  ],
};

/** The flat config to spread into your `eslint.config.js`. */
export const aegisSecurity: readonly FlatConfig[] = [
  {
    name: 'aegis/security',
    files: ['**/*.{ts,tsx,js,jsx,mjs,cjs}'],
    rules: aegisSecurityRules,
  },
];

export default aegisSecurity;
