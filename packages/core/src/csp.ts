/**
 * Content-Security-Policy builder.
 *
 * Design goals (each fixes a real bug observed in production apps):
 *  - **One serialization point.** `buildCspHeader` is the only thing that produces a CSP
 *    string, and it always injects the request nonce into `script-src`. Adapters emit it
 *    once. This structurally prevents the "nonce minted but a separate static policy is
 *    actually sent" bug (a nonce that never reaches the header → dead weight).
 *  - **No silent `nonce` + `'unsafe-inline'` mix.** Under `strict-dynamic` (the default),
 *    host allowlists and `'unsafe-inline'` are dropped from `script-src` because CSP3
 *    browsers ignore them anyway; mixing them only weakens CSP1 browsers. Re-enabling the
 *    inline fallback is an explicit, documented downgrade (`legacyUnsafeInlineFallback`).
 */

import { randomBase64Url } from './internal/encoding';

declare const NONCE_BRAND: unique symbol;
/** A minted CSP nonce. Branded so a raw string can't be passed where a real nonce is required. */
export type Nonce = string & { readonly [NONCE_BRAND]: 'CspNonce' };

declare const HOST_BRAND: unique symbol;
/** A validated CSP host/scheme source (e.g. `https://x.com`, `*.x.com`, `data:`). */
export type CspHost = string & { readonly [HOST_BRAND]: 'CspHost' };

/** Generate a 128-bit nonce (URL-safe base64). Edge/Node/browser-safe via Web Crypto. */
export function generateNonce(): Nonce {
  return randomBase64Url(16) as Nonce;
}

/** The closed set of CSP source keywords. A free string cannot smuggle one of these in as a "host". */
export type CspKeyword =
  | "'self'"
  | "'none'"
  | "'strict-dynamic'"
  | "'unsafe-inline'"
  | "'unsafe-eval'"
  | "'wasm-unsafe-eval'"
  | "'unsafe-hashes'"
  | "'report-sample'";

/** A subresource hash source, e.g. `{ hash: 'sha256-…' }`. */
export interface CspHashSource {
  readonly hash: `sha256-${string}` | `sha384-${string}` | `sha512-${string}`;
}

export type CspSource = CspKeyword | CspHost | CspHashSource;

/** Strongly-typed CSP directive model. Keys are the real directive names. */
export interface CspDirectives {
  readonly 'default-src'?: readonly CspSource[];
  readonly 'script-src'?: readonly CspSource[];
  readonly 'style-src'?: readonly CspSource[];
  readonly 'img-src'?: readonly CspSource[];
  readonly 'connect-src'?: readonly CspSource[];
  readonly 'font-src'?: readonly CspSource[];
  readonly 'frame-src'?: readonly CspSource[];
  readonly 'frame-ancestors'?: readonly CspSource[];
  readonly 'form-action'?: readonly CspSource[];
  readonly 'base-uri'?: readonly CspSource[];
  readonly 'object-src'?: readonly CspSource[];
  readonly 'worker-src'?: readonly CspSource[];
  readonly 'manifest-src'?: readonly CspSource[];
  readonly 'media-src'?: readonly CspSource[];
  readonly 'upgrade-insecure-requests'?: boolean;
  readonly 'block-all-mixed-content'?: boolean;
  readonly 'report-uri'?: string;
  readonly 'report-to'?: string;
}

export type CspMode = 'enforce' | 'report-only' | 'off';

export interface CspPolicyConfig {
  readonly directives: CspDirectives;
  /**
   * Add `'strict-dynamic'` to `script-src` and drop inert host/`'self'`/`'unsafe-inline'`
   * sources from it (CSP3 browsers ignore those once a nonce + strict-dynamic are present).
   * Default `true`.
   */
  readonly strictDynamic?: boolean;
  /**
   * @deprecated Security downgrade. Re-adds `'unsafe-inline'` to `script-src` as a CSP1
   * fallback, which disables inline-script protection on legacy browsers. Only set this if
   * you have measured a need; the hardened defaults never do.
   */
  readonly legacyUnsafeInlineFallback?: boolean;
}

export interface BuiltCspHeader {
  readonly name: 'Content-Security-Policy' | 'Content-Security-Policy-Report-Only';
  readonly value: string;
  readonly nonce: Nonce;
  /**
   * Value for a companion `Reporting-Endpoints` header, emitted only when both `report-to`
   * and `report-uri` are configured.
   */
  readonly reportingEndpoints?: string;
}

const HOST_FORBIDDEN = /[\s'";,]/u;
const SCHEME_ONLY = /^(?:https?|wss?|data|blob|mediastream|filesystem):$/iu;
const HOST_PATTERN = /^(?:(?:https?|wss?):\/\/)?(?:\*\.)?[a-z0-9.-]+(?::\d+)?(?:\/\S*)?$/iu;

function isValidCspHost(value: string): boolean {
  if (value.length === 0 || value.length > 2048) {
    return false;
  }
  // Reject quotes/whitespace/delimiters so a keyword like `'unsafe-inline'` can never be
  // accepted as a host — this is what makes the keyword/host distinction sound.
  if (HOST_FORBIDDEN.test(value)) {
    return false;
  }
  return value === '*' || SCHEME_ONLY.test(value) || HOST_PATTERN.test(value);
}

/** Smart constructor for a CSP host source. Throws on invalid input (fail-fast at config time). */
export function cspHost(value: string): CspHost {
  if (!isValidCspHost(value)) {
    throw new TypeError(`Invalid CSP host source: ${JSON.stringify(value)}`);
  }
  return value as CspHost;
}

function isKeyword(source: string): boolean {
  return source.startsWith("'");
}

function serializeSource(source: CspSource): string {
  if (typeof source === 'string') {
    return source;
  }
  return `'${source.hash}'`;
}

/** Build the `script-src` token list: always nonce'd, strict-dynamic-aware, never a silent inline mix. */
function serializeScriptSrc(
  sources: readonly CspSource[] | undefined,
  nonce: Nonce,
  strictDynamic: boolean,
  legacy: boolean,
): string[] {
  const tokens: string[] = [`'nonce-${nonce}'`];
  if (strictDynamic) {
    tokens.push("'strict-dynamic'");
  }
  for (const source of sources ?? []) {
    if (typeof source !== 'string') {
      tokens.push(serializeSource(source)); // hashes are honored even under strict-dynamic
      continue;
    }
    if (source === "'unsafe-inline'") {
      continue; // handled only via the explicit legacy fallback below
    }
    if (strictDynamic) {
      if (!isKeyword(source)) {
        continue; // host allowlists are ignored under strict-dynamic
      }
      if (source === "'self'") {
        continue; // 'self' is also ignored under strict-dynamic
      }
    }
    tokens.push(source);
  }
  if (legacy) {
    tokens.push("'unsafe-inline'");
  }
  return [...new Set(tokens)];
}

const ARRAY_DIRECTIVE_ORDER = [
  'default-src',
  'script-src',
  'style-src',
  'img-src',
  'font-src',
  'connect-src',
  'frame-src',
  'frame-ancestors',
  'form-action',
  'base-uri',
  'object-src',
  'worker-src',
  'manifest-src',
  'media-src',
] as const;

/**
 * Serialize a policy to exactly one header (name + value), or `null` when mode is `off`.
 * The nonce is injected into `script-src` here — this is the single source of truth.
 */
export function buildCspHeader(
  policy: CspPolicyConfig,
  nonce: Nonce,
  mode: CspMode,
): BuiltCspHeader | null {
  if (mode === 'off') {
    return null;
  }
  const { directives, strictDynamic = true, legacyUnsafeInlineFallback = false } = policy;
  const parts: string[] = [];

  for (const name of ARRAY_DIRECTIVE_ORDER) {
    if (name === 'script-src') {
      const tokens = serializeScriptSrc(
        directives['script-src'],
        nonce,
        strictDynamic,
        legacyUnsafeInlineFallback,
      );
      parts.push(`script-src ${tokens.join(' ')}`);
      continue;
    }
    const sources = directives[name];
    if (sources && sources.length > 0) {
      parts.push(`${name} ${sources.map(serializeSource).join(' ')}`);
    }
  }

  if (directives['upgrade-insecure-requests']) {
    parts.push('upgrade-insecure-requests');
  }
  if (directives['block-all-mixed-content']) {
    parts.push('block-all-mixed-content');
  }

  const reportUri = directives['report-uri'];
  if (reportUri) {
    parts.push(`report-uri ${reportUri}`);
  }
  const reportTo = directives['report-to'];
  if (reportTo) {
    parts.push(`report-to ${reportTo}`);
  }

  const name =
    mode === 'enforce' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
  const reportingEndpoints = reportTo && reportUri ? `${reportTo}="${reportUri}"` : undefined;

  return {
    name,
    value: parts.join('; '),
    nonce,
    ...(reportingEndpoints !== undefined ? { reportingEndpoints } : {}),
  };
}

/** Resolve a CSP mode from an env string, defaulting safely to `report-only`. */
export function resolveCspMode(
  raw: string | undefined,
  fallback: CspMode = 'report-only',
): CspMode {
  switch (raw) {
    case 'enforce':
    case 'report-only':
    case 'off':
      return raw;
    default:
      return fallback;
  }
}

export interface HardenedCspOptions {
  /** Extra `connect-src` hosts (APIs, websockets, Supabase, analytics). */
  readonly connect?: readonly string[];
  /** Extra `img-src` hosts (CDNs, avatars). */
  readonly img?: readonly string[];
  /** Extra `frame-src` hosts (Stripe, embeds). */
  readonly frame?: readonly string[];
  /** A `report-to` group name; pairs with a `Reporting-Endpoints` header and `report-uri`. */
  readonly reportTo?: string;
  /** The endpoint path/URL CSP violations are POSTed to (used for `report-uri`/`report-to`). */
  readonly reportEndpoint?: string;
}

/**
 * A hardened, Supabase/Stripe-friendly baseline. `script-src` is nonce + strict-dynamic;
 * `style-src` permits `'unsafe-inline'` (a deliberate, low-risk trade-off — styling
 * frameworks inject inline styles, and style injection is far less dangerous than script
 * injection). `object-src`/`base-uri` are locked, `frame-ancestors` denied (clickjacking).
 */
export function hardenedCspPolicy(options: HardenedCspOptions = {}): CspPolicyConfig {
  const self: CspKeyword = "'self'";
  const directives: CspDirectives = {
    'default-src': [self],
    'script-src': [self],
    'style-src': [self, "'unsafe-inline'"],
    'img-src': [self, cspHost('data:'), cspHost('blob:'), ...(options.img ?? []).map(cspHost)],
    'font-src': [self, cspHost('data:')],
    'connect-src': [self, ...(options.connect ?? []).map(cspHost)],
    'frame-src': [...(options.frame ?? []).map(cspHost)],
    'frame-ancestors': ["'none'"],
    'form-action': [self],
    'base-uri': ["'none'"],
    'object-src': ["'none'"],
    'upgrade-insecure-requests': true,
    ...(options.reportTo !== undefined && options.reportEndpoint !== undefined
      ? { 'report-to': options.reportTo, 'report-uri': options.reportEndpoint }
      : {}),
  };
  return { directives, strictDynamic: true };
}
