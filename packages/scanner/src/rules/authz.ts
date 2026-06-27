import { findExportedFunction, ts } from '../internal/ast';
import { traceOf } from '../internal/dataflow';
import { OWNERSHIP_COLUMN_PATTERN, OWNERSHIP_COLUMNS } from '../internal/ownership-columns';
import { calleeName, collectCalls, hasAnyToken } from '../internal/patterns';
import type { TaintFlow, TaintSink, TaintSpec } from '../internal/taint-descriptors';
import { docsUrlFor, type Rule, type RuleContext } from '../rule';

/**
 * Signs the query is access-controlled: an auth/session lookup, a require-guard, or a deny path. A
 * regex (not a substring list) so it recognizes the common naming that wraps auth in a helper —
 * `getAdminUser()`, `getCurrentUser()`, `requireAdmin()`, `ensureSession()`, a `forbidden()`/
 * `unauthorized()` deny — which a literal substring like `getuser(` misses (`getAdminUser` has no
 * `getuser` substring). Matching the gate, not its exact spelling, is what keeps this low-noise.
 */
const AUTH_GATE =
  /\bget\w*(?:user|admin|session|account|viewer)\b|\brequire\w*(?:user|auth|admin|session|role|login)\b|\bensure\w*(?:user|auth|admin|session)\b|\b(?:forbidden|unauthorized|currentuser|getserversession|getauth|withauth)\b|auth\.(?:uid|getuser)/i;
const OWNERSHIP_TOKENS = [
  'user_id',
  'owner_id',
  'tenant_id',
  'organization_id',
  'account_id',
  'profile_id',
  "eq('user",
  'eq("user',
];

// An auth primitive a helper's body calls — proves the helper authenticates even if its NAME does not
// match `AUTH_GATE` (e.g. `ensureCaller()` whose body calls `auth.getUser()`).
const AUTH_PRIMITIVE = /auth\s*\.\s*getuser|auth\s*\.\s*uid|\bgetsession\s*\(|\bgetuser\s*\(/i;

// Stdlib `.from(...)` factories that are NOT data queries — excluded so a route handler doing
// `Array.from(...)` / `Buffer.from(...)` is never mistaken for an unguarded table access (false positive).
const BUILTIN_FROM_RECEIVERS: ReadonlySet<string> = new Set([
  'Array',
  'Buffer',
  'Object',
  'Date',
  'String',
  'Number',
  'BigInt',
  'Set',
  'Map',
  'Int8Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int16Array',
  'Uint16Array',
  'Int32Array',
  'Uint32Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array',
]);

// The service-role/admin Supabase client bypasses RLS by design to reach arbitrary rows, so a
// request-scoped filter there is intentional cross-principal access, not an IDOR. Mirrors the same
// guard in `correlate-rls`. (Service-role *placement* is governed by `supabase/service-role-outside-admin`.)
const SERVICE_ROLE_HINT = /createAdminClient|service_role|SERVICE_ROLE/;

/**
 * A `<client>.from('<table>')` data query: the `from` method called with a string-literal table name
 * on a receiver that is not a stdlib factory. The string-literal requirement alone excludes
 * `Array.from(iterable)`/`Buffer.from(buf)`; the receiver check also excludes `Buffer.from('a','hex')`.
 */
function isSupabaseFromCall(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== 'from') {
    return false;
  }
  const arg = call.arguments[0];
  if (!arg || !ts.isStringLiteralLike(arg)) {
    return false;
  }
  const receiver = call.expression.expression;
  return !(ts.isIdentifier(receiver) && BUILTIN_FROM_RECEIVERS.has(receiver.text));
}

// ── Ownership-filter dataflow (IDOR) ─────────────────────────────────────────────────────────────
// `OWNERSHIP_COLUMNS` (the principal-scoping columns) and `OWNERSHIP_COLUMN_PATTERN` (a cheap presence
// pre-filter so a file without one can skip the taint pass) are the shared authoritative list, also
// consumed by the SQL model and the owner-scoping RLS rule — see `internal/ownership-columns`.

// PostgREST comparison filters where the column is arg0 and the compared value is arg1.
const COMPARISON_FILTERS: ReadonlySet<string> = new Set([
  'eq',
  'neq',
  'gt',
  'gte',
  'lt',
  'lte',
  'like',
  'ilike',
  'is',
  'in',
  'contains',
  'containedBy',
]);

function isOwnershipColumnArg(arg: ts.Expression | undefined): boolean {
  return arg !== undefined && ts.isStringLiteralLike(arg) && OWNERSHIP_COLUMNS.has(arg.text);
}

function isOwnershipKey(name: ts.PropertyName): boolean {
  return (
    (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && OWNERSHIP_COLUMNS.has(name.text)
  );
}

/** The compared values of every ownership column in a `.match({ … })` object. */
function ownershipMatchValues(obj: ts.ObjectLiteralExpression): ts.Expression[] {
  const values: ts.Expression[] = [];
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) && isOwnershipKey(prop.name)) {
      values.push(prop.initializer);
    } else if (ts.isShorthandPropertyAssignment(prop) && OWNERSHIP_COLUMNS.has(prop.name.text)) {
      values.push(prop.name); // `.match({ user_id })` — the value is the in-scope identifier
    }
  }
  return values;
}

/**
 * The value expression(s) a PostgREST query compares against an OWNERSHIP column — the data that, if
 * attacker-controlled, is an IDOR. Covers the three shapes seen in real Supabase code: `.eq('user_id',
 * v)` (and the comparison family), `.filter('user_id', 'eq', v)`, and `.match({ user_id: v })`.
 * Returns `[]` for anything else (KISS: three concrete shapes, nothing speculative). Shaped as a
 * `TaintSink['match']` so the existing dataflow engine, not a bespoke walker, finds the flows.
 */
function ownershipFilterValues(node: ts.Node): readonly ts.Expression[] {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) {
    return [];
  }
  const method = node.expression.name.text;
  const args = node.arguments;
  if (COMPARISON_FILTERS.has(method)) {
    const value = args[1]; // `.eq('user_id', value)`
    return value && isOwnershipColumnArg(args[0]) ? [value] : [];
  }
  if (method === 'filter') {
    const value = args[2]; // `.filter('user_id', 'eq', value)`
    return value && isOwnershipColumnArg(args[0]) ? [value] : [];
  }
  if (method === 'match' && args[0] && ts.isObjectLiteralExpression(args[0])) {
    return ownershipMatchValues(args[0]);
  }
  return [];
}

/**
 * An ownership filter is a taint SINK: request input must never reach it. `category: 'sql'` situates
 * the value in its SQL-filter context, but is immaterial to this rule — authorization is not a
 * sanitization problem, so `idorTaintedScope` reports a flow whether or not it is "sanitized".
 */
const ownershipFilterSink: TaintSink = {
  id: 'supabase.ownership-filter',
  category: 'sql',
  label: 'used to scope rows by ownership (e.g. .eq("user_id", …))',
  match: ownershipFilterValues,
};

// Frozen module-level spec: the engine memoizes flows per (file, spec) on the spec's identity, so the
// two rules that consult it below share ONE taint computation per file.
const OWNERSHIP_FILTER_SPEC: TaintSpec = { sinks: [ownershipFilterSink] };

/** Request-tainted values reaching an ownership filter in this file — the proven IDOR flows. */
function taintedOwnershipFlows(ctx: RuleContext): readonly TaintFlow[] {
  return ctx.taint(OWNERSHIP_FILTER_SPEC);
}

// ── Interprocedural auth resolution ──────────────────────────────────────────────────────────────

/**
 * Depth-1 interprocedural check: does any call in this file resolve to a same-project helper whose body
 * authenticates? Reuses the engine's module graph. Fail-secure — an external or unresolvable import is
 * simply not treated as a gate (the rule then falls back to reporting).
 */
function callsAuthenticatingHelper(ctx: RuleContext): boolean {
  for (const call of collectCalls(ctx.file.sourceFile)) {
    const name = calleeName(call);
    if (!name) {
      continue;
    }
    const binding = ctx.resolveBinding(name);
    if (!binding) {
      continue;
    }
    const target = ctx.resolveModule(binding.module);
    const fn = target ? findExportedFunction(target.sourceFile, binding.importedName) : undefined;
    if (fn && target) {
      const body = fn.getText(target.sourceFile);
      if (AUTH_PRIMITIVE.test(body) || AUTH_GATE.test(body)) {
        return true;
      }
    }
  }
  return false;
}

// ── Rules ────────────────────────────────────────────────────────────────────────────────────────

/**
 * IDOR / broken-object-level-authorization is a *vertical* risk: a library cannot fix it and a scanner
 * cannot prove it (Aegis cannot see your RLS policies). This rule does what Aegis honestly can — it
 * flags, at medium confidence (never blocking CI), a data query in a request handler that shows no
 * sign of an authorization gate, so a human reviews it. It is a prompt to verify, not a verdict.
 *
 * The complementary, higher-confidence case — a query that *does* filter by ownership but on
 * attacker-controlled input — is a proven IDOR, reported by `idorTaintedScope` below.
 */
export const missingAccessFilter: Rule = {
  meta: {
    id: 'authz/missing-access-filter',
    title: 'Data query without a visible authorization check',
    severity: 'HIGH',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('authz/missing-access-filter'),
  },
  appliesTo: (file) =>
    (file.classification.isRouteHandler || file.classification.isServerAction) &&
    /\.from\s*\(/.test(file.text),
  check(ctx) {
    const text = ctx.file.text;
    // A request-scoped ownership filter (`.eq('user_id', <request value>)`) is not a scope at all but
    // an IDOR — reported at high confidence by `authz/idor-tainted-scope`. Defer to it: emitting a
    // green pass here (the ownership token IS present) would contradict that finding, and a second,
    // weaker finding would be noise. The cheap text gate skips the taint pass on the common case.
    if (OWNERSHIP_COLUMN_PATTERN.test(text) && taintedOwnershipFlows(ctx).length > 0) {
      return;
    }
    if (AUTH_GATE.test(text) || hasAnyToken(text, OWNERSHIP_TOKENS)) {
      ctx.pass('Data query is scoped by an auth check or an ownership filter.');
      return;
    }
    const fromCall = collectCalls(ctx.file.sourceFile).find(isSupabaseFromCall);
    if (!fromCall) {
      return;
    }
    // Before reporting, follow imported helpers one hop: a call to a project helper that authenticates
    // (whatever its name) is a gate the text scan can't see.
    if (callsAuthenticatingHelper(ctx)) {
      ctx.pass('Data query is gated by an imported helper that authenticates.');
      return;
    }
    ctx.report({
      node: fromCall,
      // Heuristic: Aegis cannot read RLS, so it informs without blocking CI.
      confidence: 'medium',
      message:
        'This request handler queries a table with no visible authorization check (no auth/session lookup and no owner/tenant filter) — if the table is not protected by Row Level Security, any caller may read or modify other users’ rows (IDOR).',
      remediation:
        'Confirm the calling user is authorized for these rows: fetch the session (supabase.auth.getUser()) and filter by ownership (.eq("user_id", user.id)), and/or rely on a verified RLS policy. Aegis cannot verify RLS for you.',
      evidence: '.from(…)',
    });
  },
};

/**
 * The canonical IDOR, proven by dataflow rather than guessed by text: a query that scopes rows by an
 * ownership column but binds that filter to request-controlled input — `.eq('user_id', body.userId)`.
 * Because the ownership value is attacker-chosen, any caller reads or writes another principal's rows
 * by changing it. This is high-confidence (a real source→sink flow), so it can fail CI, and — sharing
 * the `authz/` prefix — it slots into the static↔dynamic correlation, becoming "confirmed exploitable"
 * when the runtime `dast/idor` probe reproduces it.
 *
 * Why this is sound where the heuristic above is not: it does not ask "is an ownership token present?"
 * (which a tainted filter satisfies while being the bug) — it asks "is the ownership value derived
 * from the request?". A session-derived value (`user.id` from `auth.getUser()`) is not a taint source,
 * so it yields no flow and never fires.
 *
 * Deliberately NOT built with `defineTaintRule` (unlike the injection rules): authorization is not a
 * sanitization problem, so this rule must report a flow *regardless of* `flow.sanitized`, and it dedupes
 * to one finding per query site — neither of which the factory expresses. Keep the hand-rolled `check`.
 */
export const idorTaintedScope: Rule = {
  meta: {
    id: 'authz/idor-tainted-scope',
    title: 'Ownership filter bound to request-controlled input (IDOR)',
    severity: 'HIGH',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('authz/idor-tainted-scope'),
  },
  appliesTo: (file) =>
    (file.classification.isRouteHandler || file.classification.isServerAction) &&
    OWNERSHIP_COLUMN_PATTERN.test(file.text),
  check(ctx) {
    // The admin/service-role client bypasses RLS by design to reach arbitrary rows, so a request id in
    // an ownership filter there is intentional, not an IDOR — suppress to protect the zero-false-positive
    // gate that gives this CI-failing rule its authority (mirrors `correlate-rls`). Known limitation: this
    // is a whole-file text gate, so a file that ALSO contains a genuine anon-client IDOR is not flagged.
    // We accept that false negative over a false positive on a blocking rule; scoping the check to the
    // flow's actual client is future work.
    if (SERVICE_ROLE_HINT.test(ctx.file.text)) {
      return;
    }
    const reported = new Set<number>();
    for (const flow of taintedOwnershipFlows(ctx)) {
      // One finding per query site (a `.match({ user_id, tenant_id })` yields a flow per column).
      const at = flow.sink.getStart(ctx.file.sourceFile);
      if (reported.has(at)) {
        continue;
      }
      reported.add(at);
      // Reported regardless of `flow.sanitized`: sanitization makes a value safe to INTERPOLATE (an
      // injection concern); it does nothing for AUTHORIZATION. `Number(params.id)` is still an
      // attacker-CHOSEN id. The only safe ownership value comes from the session — which, not being a
      // taint source, produces no flow at all — so any flow that reaches here is a real IDOR.
      ctx.report({
        node: flow.sink,
        confidence: flow.confidence,
        message:
          'This query scopes rows by an ownership column (e.g. user_id) using a value taken from the request — any caller can read or modify another user’s rows by changing it (IDOR / broken object-level authorization).',
        remediation:
          'Derive the ownership value from the authenticated session, never the request: `const { data: { user } } = await supabase.auth.getUser(); … .eq("user_id", user.id)`. Back it with an RLS policy that scopes rows to `auth.uid()`. A user/tenant id supplied by the caller must never select which rows it can see.',
        evidence: flow.source.getText(ctx.file.sourceFile),
        trace: traceOf(ctx.file, flow),
      });
    }
  },
};
