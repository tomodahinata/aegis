/**
 * Security response headers, as a typed config → `[name, value]` tuples. Pairs with the
 * CSP builder so a single adapter emits the full hardened set in one place. A `false` value
 * omits a header entirely (so callers can opt out of one without re-specifying the rest).
 */

export type ReferrerPolicyToken =
  | 'no-referrer'
  | 'no-referrer-when-downgrade'
  | 'origin'
  | 'origin-when-cross-origin'
  | 'same-origin'
  | 'strict-origin'
  | 'strict-origin-when-cross-origin'
  | 'unsafe-url';

export type PermissionsFeature =
  | 'accelerometer'
  | 'autoplay'
  | 'browsing-topics'
  | 'camera'
  | 'display-capture'
  | 'encrypted-media'
  | 'fullscreen'
  | 'geolocation'
  | 'gyroscope'
  | 'magnetometer'
  | 'microphone'
  | 'midi'
  | 'payment'
  | 'usb'
  | 'xr-spatial-tracking';

export interface HstsConfig {
  /** Seconds. Use ≥ 31536000 (1y) for `preload`. */
  readonly maxAge: number;
  readonly includeSubDomains?: boolean;
  readonly preload?: boolean;
}

export interface SecurityHeadersConfig {
  readonly hsts?: HstsConfig | false;
  /** Legacy clickjacking control; modern apps should also use CSP `frame-ancestors`. */
  readonly frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** `X-Content-Type-Options: nosniff`. */
  readonly contentTypeOptions?: boolean;
  readonly referrerPolicy?: ReferrerPolicyToken | false;
  /** Map of feature → allowlist. `[]` denies the feature for everyone (`feature=()`). */
  readonly permissionsPolicy?: Partial<Record<PermissionsFeature, readonly string[]>> | false;
  readonly coop?: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none' | false;
  readonly coep?: 'require-corp' | 'credentialless' | 'unsafe-none' | false;
  readonly corp?: 'same-origin' | 'same-site' | 'cross-origin' | false;
}

/** Sensible, broadly-compatible hardened defaults. COEP is off (it breaks many third-party embeds). */
export const HARDENED_HEADERS: SecurityHeadersConfig = {
  hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: false },
  frameOptions: 'SAMEORIGIN',
  contentTypeOptions: true,
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: { camera: [], microphone: [], geolocation: [], 'browsing-topics': [] },
  coop: 'same-origin',
  coep: false,
  corp: 'same-origin',
};

/** Cross-origin-isolated, maximally locked variant. Enables COEP and HSTS preload; test before shipping. */
export const STRICT_HEADERS: SecurityHeadersConfig = {
  hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
  frameOptions: 'DENY',
  contentTypeOptions: true,
  referrerPolicy: 'no-referrer',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    'browsing-topics': [],
    payment: [],
    usb: [],
  },
  coop: 'same-origin',
  coep: 'require-corp',
  corp: 'same-origin',
};

function serializeHsts(hsts: HstsConfig): string {
  if (hsts.preload && !hsts.includeSubDomains) {
    throw new TypeError('HSTS `preload` requires `includeSubDomains: true`.');
  }
  if (hsts.preload && hsts.maxAge < 31_536_000) {
    throw new TypeError('HSTS `preload` requires `maxAge` of at least 31536000 (1 year).');
  }
  const parts = [`max-age=${Math.floor(hsts.maxAge)}`];
  if (hsts.includeSubDomains) {
    parts.push('includeSubDomains');
  }
  if (hsts.preload) {
    parts.push('preload');
  }
  return parts.join('; ');
}

function serializePermissionsPolicy(
  policy: Partial<Record<PermissionsFeature, readonly string[]>>,
): string {
  const entries: string[] = [];
  for (const [feature, allowlist] of Object.entries(policy)) {
    if (allowlist === undefined) {
      continue;
    }
    const items = allowlist
      .map((origin) => (origin === 'self' || origin === '*' ? origin : `"${origin}"`))
      .join(' ');
    entries.push(`${feature}=(${items})`);
  }
  return entries.join(', ');
}

/** Build the configured security headers as `[name, value]` tuples (CSP is handled separately). */
export function buildSecurityHeaders(
  config: SecurityHeadersConfig,
): ReadonlyArray<readonly [name: string, value: string]> {
  const headers: Array<readonly [string, string]> = [];

  if (config.hsts) {
    headers.push(['Strict-Transport-Security', serializeHsts(config.hsts)]);
  }
  if (config.frameOptions) {
    headers.push(['X-Frame-Options', config.frameOptions]);
  }
  if (config.contentTypeOptions) {
    headers.push(['X-Content-Type-Options', 'nosniff']);
  }
  if (config.referrerPolicy) {
    headers.push(['Referrer-Policy', config.referrerPolicy]);
  }
  if (config.permissionsPolicy) {
    const value = serializePermissionsPolicy(config.permissionsPolicy);
    if (value.length > 0) {
      headers.push(['Permissions-Policy', value]);
    }
  }
  if (config.coop) {
    headers.push(['Cross-Origin-Opener-Policy', config.coop]);
  }
  if (config.coep) {
    headers.push(['Cross-Origin-Embedder-Policy', config.coep]);
  }
  if (config.corp) {
    headers.push(['Cross-Origin-Resource-Policy', config.corp]);
  }

  return headers;
}
