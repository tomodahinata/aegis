import { ts } from '../internal/ast';
import { type CspContext, type CspUnsafeKeyword, findCspUnsafeUses } from '../internal/csp';
import { collectStringLikes, type StringLike } from '../internal/patterns';
import { docsUrlFor, type Rule } from '../rule';
import type { Confidence, Severity } from '../types';

const CSP_DIRECTIVE = /script-src|style-src|default-src/i;

// A DEVELOPMENT-positive condition. We suppress an unsafe directive only when it sits in the TRUE
// branch of such a condition (never a prod-positive one like `NODE_ENV === 'production'`), so a real
// production finding can never be hidden — at worst an unrecognized dev gate leaves a benign finding.
const DEV_CONDITION =
  /\bis_?dev(?:elopment)?\b|\b__DEV__\b|NODE_ENV\s*!==?\s*['"`]production['"`]|NODE_ENV\s*===?\s*['"`]development['"`]/i;

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

/** True if `node` is in the development-only branch of a `dev ? … : …` / `if (dev) { … }`. */
function isDevelopmentOnly(node: ts.Node, sourceFile: ts.SourceFile): boolean {
  let child: ts.Node = node;
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (
      ts.isConditionalExpression(current) &&
      child === current.whenTrue &&
      DEV_CONDITION.test(current.condition.getText(sourceFile))
    ) {
      return true;
    }
    if (
      ts.isIfStatement(current) &&
      child === current.thenStatement &&
      DEV_CONDITION.test(current.expression.getText(sourceFile))
    ) {
      return true;
    }
    if (isFunctionLike(current)) {
      return false; // do not cross a function boundary
    }
    child = current;
    current = current.parent;
  }
  return false;
}

/** String-likes whose own text names a CSP directive (the policy "head" of a split policy). */
function cspDirectiveStringLikes(sourceFile: ts.SourceFile): StringLike[] {
  return collectStringLikes(sourceFile).filter((s) => CSP_DIRECTIVE.test(s.text));
}

interface Verdict {
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly message: string;
  readonly remediation: string;
  /** Directive-qualified evidence — also distinguishes script vs style in SARIF fingerprints. */
  readonly evidence: string;
}

const NONCE_FIX =
  "Drop 'unsafe-inline' and use a per-request nonce + 'strict-dynamic' (e.g. @aegiskit/next `secure()`).";

// Impact (severity) × certainty (confidence) for each keyword in each directive context.
// `unknown` is scored fail-secure (as script context) but messaged honestly. Keying the record by
// the full `keyword:context` union makes the table exhaustive — a missing case fails to type-check.
const VERDICTS: Record<`${CspUnsafeKeyword}:${CspContext}`, Verdict> = {
  'unsafe-inline:script': {
    severity: 'HIGH',
    confidence: 'high',
    message:
      "Content-Security-Policy script-src allows 'unsafe-inline' — injected inline scripts can execute, defeating CSP's core XSS protection.",
    remediation: NONCE_FIX,
    evidence: "script-src 'unsafe-inline'",
  },
  'unsafe-inline:unknown': {
    severity: 'HIGH',
    confidence: 'high',
    message:
      "Content-Security-Policy allows 'unsafe-inline' in a fragment whose directive could not be determined; scored as script-src (worst case) — injected inline scripts could execute.",
    remediation: NONCE_FIX,
    evidence: "'unsafe-inline'",
  },
  'unsafe-inline:style': {
    severity: 'MEDIUM',
    confidence: 'high',
    message:
      "Content-Security-Policy style-src allows 'unsafe-inline'. This permits injected inline styles (CSS exfiltration / UI redressing) but NOT script execution — materially lower risk than a script-src bypass.",
    remediation:
      'Prefer nonced or hashed styles. If your framework cannot nonce inline styles end-to-end yet (e.g. Next.js / Tailwind), track it and tighten once supported.',
    evidence: "style-src 'unsafe-inline'",
  },
  'unsafe-eval:script': {
    severity: 'HIGH',
    confidence: 'medium',
    message:
      "Content-Security-Policy script-src allows 'unsafe-eval', permitting string-to-code execution (eval / new Function).",
    remediation:
      "Remove 'unsafe-eval'. If a dependency truly needs it, scope it as narrowly as possible — and ideally only in development.",
    evidence: "script-src 'unsafe-eval'",
  },
  'unsafe-eval:unknown': {
    severity: 'HIGH',
    confidence: 'medium',
    message:
      "Content-Security-Policy allows 'unsafe-eval' in a fragment whose directive could not be determined; scored as script-src (worst case) — string-to-code execution could be permitted.",
    remediation:
      "Remove 'unsafe-eval'. If a dependency truly needs it, scope it as narrowly as possible — and ideally only in development.",
    evidence: "'unsafe-eval'",
  },
  'unsafe-eval:style': {
    severity: 'LOW',
    confidence: 'low',
    message:
      "Content-Security-Policy style-src lists 'unsafe-eval', which has no effect on style injection — it only muddies the policy's intent.",
    remediation: "Remove 'unsafe-eval' from style-src; it grants nothing.",
    evidence: "style-src 'unsafe-eval'",
  },
};

export const cspUnsafeInline: Rule = {
  meta: {
    id: 'csp/unsafe-inline',
    title: "CSP allows 'unsafe-inline'/'unsafe-eval'",
    severity: 'HIGH',
    owasp: 'A05:2021 Security Misconfiguration',
    docsUrl: docsUrlFor('csp/unsafe-inline'),
  },
  appliesTo: (file) => /content-security-policy|script-src|style-src/i.test(file.text),
  check(ctx) {
    // The file is already a CSP context (gated by `appliesTo`). Each string-like is parsed into its
    // directive segments so every unsafe keyword is scored by the directive it actually sits in —
    // even an array-split fragment like `'unsafe-inline'` that names no directive of its own.
    for (const s of collectStringLikes(ctx.file.sourceFile)) {
      const uses = findCspUnsafeUses(s.text);
      if (uses.length === 0) {
        continue;
      }
      // A directive emitted only in a `dev ? … : …` branch never ships to production — not a finding.
      if (isDevelopmentOnly(s.node, ctx.file.sourceFile)) {
        ctx.pass('CSP unsafe directive is gated to development only (not shipped to production).');
        continue;
      }
      for (const { keyword, context } of uses) {
        const verdict = VERDICTS[`${keyword}:${context}`];
        ctx.report({
          node: s.node,
          severity: verdict.severity,
          confidence: verdict.confidence,
          message: verdict.message,
          remediation: verdict.remediation,
          evidence: verdict.evidence,
        });
      }
    }
  },
};

export const cspNonceMintedUnused: Rule = {
  meta: {
    id: 'csp/nonce-minted-unused',
    title: 'CSP nonce minted but never used',
    severity: 'HIGH',
    owasp: 'A05:2021 Security Misconfiguration',
    docsUrl: docsUrlFor('csp/nonce-minted-unused'),
  },
  appliesTo: (file) =>
    (file.classification.isConfig || file.classification.isMiddleware) && /nonce/i.test(file.text),
  check(ctx) {
    const mintsNonce =
      /generatenonce|randomuuid|nanoid/i.test(ctx.file.text) ||
      /x-[a-z-]*nonce/i.test(ctx.file.text);
    if (!mintsNonce) {
      return;
    }
    for (const s of cspDirectiveStringLikes(ctx.file.sourceFile)) {
      if (s.text.includes("'unsafe-inline'") && !s.text.includes('nonce-')) {
        ctx.report({
          node: s.node,
          confidence: 'medium',
          message:
            "A nonce is generated, but the emitted CSP uses 'unsafe-inline' and never references it — the nonce is dead weight and inline scripts stay unprotected.",
          remediation:
            'Emit the CSP from one place that injects the nonce (e.g. @aegiskit/next `secure()`), and delete any static unsafe-inline policy.',
        });
        return; // one finding per file is enough to flag the pattern
      }
    }
  },
};
