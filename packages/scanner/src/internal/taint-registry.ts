/**
 * The shared vocabulary data: which expressions introduce untrusted input (SOURCES), which transforms
 * render it safe and for which sink categories (SANITIZERS), and which preserve taint verbatim
 * (PASS_THROUGH). Every taint rule reuses this set; rules contribute only their sinks. Adding "`cookies().get()`
 * is a source" is a one-line edit here with its own test — it touches neither the algorithm nor any rule.
 *
 * Matchers use `node.getText()` (no `SourceFile` arg) — safe because the engine only ever feeds nodes
 * parsed with `setParentNodes`, so the parent chain to the `SourceFile` exists.
 */

import { ts } from './ast';
import {
  ALL_SINK_CATEGORIES,
  type SinkCategory,
  type TaintSanitizer,
  type TaintSource,
} from './taint-descriptors';

// ── Sources ────────────────────────────────────────────────────────────────────────────────────

function isPropertyCall(node: ts.Node, names: ReadonlySet<string>): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    names.has(node.expression.name.text)
  );
}

const GETTERS: ReadonlySet<string> = new Set(['get', 'getAll']);
const BODY_READERS: ReadonlySet<string> = new Set([
  'json',
  'text',
  'formData',
  'arrayBuffer',
  'blob',
]);

/** `…searchParams.get('q')` / `.getAll(…)` — the receiver chain mentions `searchParams`. */
function isSearchParam(node: ts.Node): boolean {
  return (
    isPropertyCall(node, GETTERS) &&
    /\bsearchParams\b/.test((node.expression as ts.PropertyAccessExpression).expression.getText())
  );
}

/** `req.json()` / `request.text()` / `req.formData()` — an awaited request-body read. */
function isRequestBody(node: ts.Node): boolean {
  if (!isPropertyCall(node, BODY_READERS)) {
    return false;
  }
  return /\b(?:req|request)\b/.test(
    (node.expression as ts.PropertyAccessExpression).expression.getText(),
  );
}

/** `.get(…)` on a request-input factory: `cookies()`, `headers()`, or `useSearchParams()`. */
const GETTER_FACTORIES: ReadonlySet<string> = new Set(['cookies', 'headers', 'useSearchParams']);
function isFactoryGet(node: ts.Node): boolean {
  if (!isPropertyCall(node, GETTERS)) {
    return false;
  }
  const receiver = (node.expression as ts.PropertyAccessExpression).expression;
  return (
    ts.isCallExpression(receiver) &&
    ts.isIdentifier(receiver.expression) &&
    GETTER_FACTORIES.has(receiver.expression.text)
  );
}

/** Client-side URL input: `location.search` / `location.hash` / `window.location.href`. */
const LOCATION_PROPS: ReadonlySet<string> = new Set(['search', 'hash', 'href']);
function isLocationInput(node: ts.Node): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    LOCATION_PROPS.has(node.name.text) &&
    /\blocation\b/.test(node.expression.getText())
  );
}

/** `process.argv` / `process.argv[n]` — CLI input. */
function isProcessArgv(node: ts.Node): boolean {
  const access = ts.isElementAccessExpression(node) ? node.expression : node;
  return (
    ts.isPropertyAccessExpression(access) &&
    ts.isIdentifier(access.expression) &&
    access.expression.text === 'process' &&
    access.name.text === 'argv'
  );
}

export const SOURCES: readonly TaintSource[] = [
  {
    id: 'next.searchParams',
    label: 'URL query parameter',
    match: isSearchParam,
    confidence: 'high',
  },
  { id: 'next.requestBody', label: 'request body', match: isRequestBody, confidence: 'high' },
  {
    id: 'next.factoryGet',
    label: 'cookie/header/query value',
    match: isFactoryGet,
    confidence: 'high',
  },
  { id: 'dom.location', label: 'URL (location)', match: isLocationInput, confidence: 'high' },
  { id: 'node.argv', label: 'process.argv', match: isProcessArgv, confidence: 'high' },
];

/**
 * Route/page parameter names that App Router binds to untrusted URL segments. Seeded at the scope
 * boundary (a function parameter named one of these), not as an expression matcher.
 */
export const PARAM_SOURCE_NAMES: ReadonlySet<string> = new Set(['params', 'searchParams']);

// ── Sanitizers ─────────────────────────────────────────────────────────────────────────────────

const NUMERIC_CASTS: ReadonlySet<string> = new Set(['Number', 'parseInt', 'parseFloat', 'BigInt']);

function isIdentCall(
  node: ts.CallExpression | ts.NewExpression,
  names: ReadonlySet<string>,
): boolean {
  return (
    ts.isCallExpression(node) && ts.isIdentifier(node.expression) && names.has(node.expression.text)
  );
}

/** A Zod (or Zod-shaped) `.parse`/`.safeParse` whose schema CONSTRAINS the value to a safe shape. */
function isConstrainedParse(node: ts.CallExpression | ts.NewExpression): boolean {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) {
    return false;
  }
  const method = node.expression.name.text;
  if (method !== 'parse' && method !== 'safeParse') {
    return false;
  }
  // A plain `z.string().parse(x)` does NOT make `x` safe for SQL/shell — only a constraining schema
  // (number/uuid/enum/regex/…) does. We read the schema's source text, fail-secure to "not a sanitizer".
  return /\.(?:number|int|boolean|uuid|email|enum|literal|regex|datetime|ip|url)\s*\(|coerce\.(?:number|boolean|date)/.test(
    node.expression.expression.getText(),
  );
}

const URL_ENCODERS: ReadonlySet<string> = new Set(['encodeURIComponent', 'encodeURI']);

/** `new URL(taintedPath, FIXED_BASE)` pins the host → safe for `url` sinks (SSRF/open-redirect). */
function isFixedBaseUrl(node: ts.CallExpression | ts.NewExpression): boolean {
  return (
    ts.isNewExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === 'URL' &&
    (node.arguments?.length ?? 0) >= 2
  );
}

/** `path.basename(x)` / imported `basename(x)` strips traversal segments → safe for `fs-path` sinks. */
function isPathBasename(node: ts.CallExpression | ts.NewExpression): boolean {
  if (!ts.isCallExpression(node)) {
    return false;
  }
  const callee = node.expression;
  if (ts.isPropertyAccessExpression(callee)) {
    return callee.name.text === 'basename';
  }
  return ts.isIdentifier(callee) && callee.text === 'basename';
}

const HTML_SANITIZER = /^(?:sanitize|purify|clean|escapeHtml|dompurify)/i;

/** `DOMPurify.sanitize(x)`, a `sanitize*`/`escapeHtml*` call, or `JSON.stringify(x)` → safe for `html`. */
function isHtmlSanitizer(node: ts.CallExpression | ts.NewExpression): boolean {
  if (!ts.isCallExpression(node)) {
    return false;
  }
  const callee = node.expression;
  if (ts.isPropertyAccessExpression(callee)) {
    if (
      ts.isIdentifier(callee.expression) &&
      callee.expression.text === 'JSON' &&
      callee.name.text === 'stringify'
    ) {
      return true;
    }
    return HTML_SANITIZER.test(callee.name.text);
  }
  return ts.isIdentifier(callee) && HTML_SANITIZER.test(callee.text);
}

export const SANITIZERS: readonly TaintSanitizer[] = [
  {
    id: 'numeric-cast',
    label: 'numeric cast',
    match: (node) => isIdentCall(node, NUMERIC_CASTS),
    argIndex: 0,
    neutralizes: ALL_SINK_CATEGORIES,
  },
  {
    id: 'schema-parse',
    label: 'schema validation',
    match: isConstrainedParse,
    argIndex: 0,
    neutralizes: ALL_SINK_CATEGORIES,
  },
  {
    id: 'url-encode',
    label: 'URL-encoding',
    match: (node) => isIdentCall(node, URL_ENCODERS),
    argIndex: 0,
    neutralizes: new Set<SinkCategory>(['url']),
  },
  {
    id: 'fixed-base-url',
    label: 'host-pinned URL',
    match: isFixedBaseUrl,
    argIndex: 0,
    neutralizes: new Set<SinkCategory>(['url']),
  },
  {
    id: 'path-basename',
    label: 'path.basename',
    match: isPathBasename,
    argIndex: 0,
    neutralizes: new Set<SinkCategory>(['fs-path']),
  },
  {
    id: 'html-sanitize',
    label: 'HTML sanitizer',
    match: isHtmlSanitizer,
    argIndex: 0,
    neutralizes: new Set<SinkCategory>(['html']),
  },
];

// ── Pass-through transforms ──────────────────────────────────────────────────────────────────────

/** String methods that preserve attacker control of their result (a substring of tainted data is tainted). */
const PASSTHROUGH_METHODS: ReadonlySet<string> = new Set([
  'trim',
  'trimStart',
  'trimEnd',
  'toLowerCase',
  'toUpperCase',
  'slice',
  'substring',
  'substr',
  'padStart',
  'padEnd',
  'at',
  'toString',
  'normalize',
  'valueOf',
]);

const PASSTHROUGH_FUNCS: ReadonlySet<string> = new Set(['String']);
/** Decoders preserve taint AND *remove* prior encoding — so they reset any neutralized categories. */
const DECODERS: ReadonlySet<string> = new Set([
  'decodeURIComponent',
  'decodeURI',
  'atob',
  'unescape',
]);
/**
 * Methods whose tainted data is the ARGUMENT, not the receiver. A `schema.parse(x)` that does not
 * constrain `x` to a safe shape (the constraining case is a sanitizer, above) validates structure but
 * leaves injection risk intact — `z.string()` accepts `'; DROP TABLE`. So taint flows from the arg.
 */
const ARG_PASSTHROUGH_METHODS: ReadonlySet<string> = new Set([
  'parse',
  'safeParse',
  'parseAsync',
  'safeParseAsync',
]);

export interface PassThrough {
  /** The expression whose taint flows to the call's result (the receiver or an argument). */
  readonly from: ts.Expression;
  /** True for decoders, which un-do encoding and thus clear any `url`/`html` neutralization. */
  readonly clearsNeutralization: boolean;
}

/**
 * If `call` merely re-shapes tainted data without sanitizing it, return the source expression its
 * result derives from. `String(x)`/`x.trim()`/`JSON.parse(x)`/`decodeURIComponent(x)` are pass-through;
 * an unrecognized call is deliberately NOT (its result is treated as clean — fail-secure against the
 * false positive of guessing an unknown helper leaks taint).
 */
export function passThroughSource(call: ts.CallExpression): PassThrough | undefined {
  const callee = call.expression;
  if (ts.isPropertyAccessExpression(callee)) {
    const method = callee.name.text;
    const isJson = ts.isIdentifier(callee.expression) && callee.expression.text === 'JSON';
    // `JSON.parse(attackerJson)` and `schema.parse(x)` both carry taint from their ARGUMENT.
    if ((isJson && method === 'parse') || (!isJson && ARG_PASSTHROUGH_METHODS.has(method))) {
      return call.arguments[0]
        ? { from: call.arguments[0], clearsNeutralization: false }
        : undefined;
    }
    if (PASSTHROUGH_METHODS.has(method)) {
      return { from: callee.expression, clearsNeutralization: false };
    }
    return undefined;
  }
  if (ts.isIdentifier(callee)) {
    if (DECODERS.has(callee.text)) {
      return call.arguments[0]
        ? { from: call.arguments[0], clearsNeutralization: true }
        : undefined;
    }
    if (PASSTHROUGH_FUNCS.has(callee.text)) {
      return call.arguments[0]
        ? { from: call.arguments[0], clearsNeutralization: false }
        : undefined;
    }
  }
  return undefined;
}
