/**
 * CSP risk analysis: attribute each `'unsafe-inline'` / `'unsafe-eval'` use to the directive
 * context it sits in, so a rule can score it by *real impact* instead of mere presence.
 *
 *   - `script`  — script-src / default-src / worker-src family. `'unsafe-inline'` here re-enables
 *                 arbitrary inline script execution (the classic XSS bypass); `'unsafe-eval'`
 *                 re-enables string-to-code (eval / new Function).
 *   - `style`   — style-src family. `'unsafe-inline'` permits inline CSS only — no script
 *                 execution — a materially lower risk than the script-src case.
 *   - `unknown` — a policy *fragment* with no directive name of its own (e.g. an array-split
 *                 `"'unsafe-inline'"`). Reported as-is; callers treat it fail-secure (worst
 *                 case = script context).
 *
 * A keyword under a directive where it has no effect (e.g. `img-src 'unsafe-inline'`, or a typo'd
 * directive the browser ignores) is NOT returned — flagging an inert keyword is a false positive.
 *
 * Pure and dependency-free: it operates on the raw source slice of a string/template literal, so
 * surrounding quotes/backticks and `${…}` interpolations are tolerated rather than stripped.
 */

export type CspContext = 'script' | 'style' | 'unknown';
export type CspUnsafeKeyword = 'unsafe-inline' | 'unsafe-eval';

export interface CspUnsafeUse {
  readonly keyword: CspUnsafeKeyword;
  readonly context: CspContext;
}

// Directives where the unsafe keywords actually have effect. Both lists are exhaustive per CSP
// Level 3; any other directive renders the keyword inert. `default-src` is the script fallback, so
// it is scored fail-secure as script context.
const SCRIPT_DIRECTIVES: ReadonlySet<string> = new Set([
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'worker-src',
  'default-src',
]);
const STYLE_DIRECTIVES: ReadonlySet<string> = new Set([
  'style-src',
  'style-src-elem',
  'style-src-attr',
]);

const UNSAFE_INLINE = "'unsafe-inline'";
const UNSAFE_EVAL = "'unsafe-eval'";

// A nonce-source or hash-source in the same directive makes `'unsafe-inline'` INERT in any CSP Level 3
// browser (the spec mandates that `'unsafe-inline'` is ignored whenever a nonce/hash is present in that
// same directive); `'strict-dynamic'` does the same for script directives. This is the *recommended*
// hardened pattern —
// `script-src 'nonce-…' 'strict-dynamic' 'unsafe-inline'` keeps `'unsafe-inline'` only as a fallback for
// legacy CSP1 browsers — so reporting it as an active XSS bypass is a false positive (Google's CSP
// Evaluator scores it the same way). `'unsafe-eval'` is NOT neutralized by either and stays reportable.
const NONCE_OR_HASH = /'nonce-|'sha(?:256|384|512)-/i;
const STRICT_DYNAMIC = "'strict-dynamic'";

/** A directive name is a bare, lowercase, dash-joined identifier (`script-src`, `default-src`). */
const DIRECTIVE_NAME = /^[a-z][a-z-]*$/;

/** The leading directive name of a `;`-split segment (lowercased), or `undefined` if it has none. */
function leadingDirective(segment: string): string | undefined {
  const first = segment.trim().split(/\s+/, 1)[0] ?? '';
  // `getText()` keeps the JS delimiter on the outer segments — drop one leading `, ", or '.
  const name = first.replace(/^[`"']/, '').toLowerCase();
  return DIRECTIVE_NAME.test(name) ? name : undefined;
}

/** `'inert'` means the keyword has no effect here, so it must not be reported. */
function contextOf(segment: string): CspContext | 'inert' {
  const name = leadingDirective(segment);
  if (name === undefined) {
    return 'unknown'; // bare fragment → caller scores fail-secure (script)
  }
  if (SCRIPT_DIRECTIVES.has(name)) {
    return 'script';
  }
  if (STYLE_DIRECTIVES.has(name)) {
    return 'style';
  }
  return 'inert'; // a real directive that ignores unsafe-inline/unsafe-eval
}

/**
 * Is `'unsafe-inline'` neutralized within this directive segment? True when a nonce/hash source is also
 * present (any directive), or `'strict-dynamic'` is present in a script directive — in either case a
 * CSP Level 3 browser ignores `'unsafe-inline'`, so it is not an active bypass. Neutralization is
 * evaluated per `;`-split segment and must stay that way: a nonce only neutralizes `'unsafe-inline'` in
 * its OWN directive, so widening this across segments would suppress a genuinely unsafe directive (a
 * fail-open).
 */
function inlineNeutralized(segment: string, context: CspContext): boolean {
  if (NONCE_OR_HASH.test(segment)) {
    return true;
  }
  return context === 'script' && segment.includes(STRICT_DYNAMIC);
}

/**
 * Every `'unsafe-inline'` / `'unsafe-eval'` use in `policyText`, paired with its directive context.
 * De-duplicated by `(keyword, context)` so one string literal yields at most one finding per pair.
 */
export function findCspUnsafeUses(policyText: string): CspUnsafeUse[] {
  const uses: CspUnsafeUse[] = [];
  const seen = new Set<string>();
  for (const segment of policyText.split(';')) {
    const present: ReadonlyArray<readonly [boolean, CspUnsafeKeyword]> = [
      [segment.includes(UNSAFE_INLINE), 'unsafe-inline'],
      [segment.includes(UNSAFE_EVAL), 'unsafe-eval'],
    ];
    if (!present.some(([has]) => has)) {
      continue;
    }
    const context = contextOf(segment);
    if (context === 'inert') {
      continue;
    }
    for (const [has, keyword] of present) {
      if (!has) {
        continue;
      }
      if (keyword === 'unsafe-inline' && inlineNeutralized(segment, context)) {
        continue; // a nonce/hash/strict-dynamic in the same directive makes 'unsafe-inline' inert (CSP3)
      }
      const key = `${keyword}:${context}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      uses.push({ keyword, context });
    }
  }
  return uses;
}
