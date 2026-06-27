/**
 * Capture an HTTP response for probe logic, and redact secrets before any of it enters a finding. A
 * DAST report can be committed or uploaded to CI/SARIF, so it must never carry a session cookie, bearer
 * token, or API key the probe happened to elicit (CLAUDE.md: never echo secrets; fail secure).
 */

import type { HttpExchange } from '@aegiskit/scanner';

export const DEFAULT_BODY_CAP = 2048;

export interface CapturedResponse {
  readonly status: number;
  /** Lower-cased single-value headers, for probe logic. */
  readonly headers: ReadonlyMap<string, string>;
  /** Raw `Set-Cookie` lines (the cookie-flags probe inspects attributes, not values). */
  readonly setCookies: readonly string[];
  /** A captured 3xx `Location` — captured, never followed (manual redirect). */
  readonly location?: string;
  readonly contentType?: string;
  /** Body capped at the byte limit (raw here; redacted when surfaced into a finding). */
  readonly body: string;
  readonly truncated: boolean;
  readonly elapsedMs: number;
}

/**
 * Read a response body bounded to `cap` characters. Streams chunk-by-chunk and stops as soon as the
 * cap is exceeded, so a hostile or oversized body (even within the per-request timeout) can never be
 * buffered unboundedly into memory (OOM). Runtime-agnostic: Web Streams + TextDecoder, available on
 * Node, Edge, and the browser (no `node:` import — keeps the probe portable).
 */
async function readBoundedBody(
  response: Response,
  cap: number,
): Promise<{ body: string; truncated: boolean }> {
  const stream = response.body;
  if (!stream) {
    const text = await response.text().catch(() => '');
    return { body: text.slice(0, cap), truncated: text.length > cap };
  }
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let body = '';
  let truncated = false;
  try {
    while (body.length <= cap) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      body += decoder.decode(value, { stream: true });
      if (body.length > cap) {
        truncated = true;
        break;
      }
    }
  } catch {
    // A partial body is still useful evidence; treat a read error like end-of-stream.
  } finally {
    await reader.cancel().catch(() => {});
  }
  return { body: body.slice(0, cap), truncated };
}

export async function captureResponse(
  response: Response,
  elapsedMs: number,
  cap: number = DEFAULT_BODY_CAP,
): Promise<CapturedResponse> {
  const headers = new Map<string, string>();
  response.headers.forEach((value, key) => {
    headers.set(key.toLowerCase(), value);
  });
  const setCookies =
    typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
  const { body, truncated } = await readBoundedBody(response, cap);
  const location = headers.get('location');
  const contentType = headers.get('content-type');
  return {
    status: response.status,
    headers,
    setCookies,
    body,
    truncated,
    elapsedMs,
    ...(location !== undefined ? { location } : {}),
    ...(contentType !== undefined ? { contentType } : {}),
  };
}

// Shapes that are secrets regardless of context — masked before any text enters a finding.
const SECRET_PATTERNS: readonly RegExp[] = [
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}/g, // JWT
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b/gi, // Stripe-style
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub token
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack token
  /\b[A-Fa-f0-9]{40,}\b/g, // long hex (HMACs, session ids)
];

/** Mask anything that looks like a credential. Conservative — only clear secret shapes. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, '[REDACTED]');
  }
  return out;
}

const SENSITIVE_HEADERS: ReadonlySet<string> = new Set([
  'set-cookie',
  'cookie',
  'authorization',
  'proxy-authorization',
  'x-aegis-signature',
]);

/** Redact a header value: sensitive headers are fully masked; others have secret substrings masked. */
export function redactHeaderValue(name: string, value: string): string {
  return SENSITIVE_HEADERS.has(name.toLowerCase()) ? '[REDACTED]' : redactSecrets(value);
}

// Headers worth keeping in a finding's evidence (security-relevant, low-noise).
const EVIDENCE_HEADERS: ReadonlySet<string> = new Set([
  'content-type',
  'location',
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
]);

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Build the redacted, truncated HTTP exchange that a dynamic finding carries as proof. */
export function toHttpExchange(
  method: string,
  path: string,
  captured: CapturedResponse,
  requestBody?: string,
): HttpExchange {
  const headers: Record<string, string> = {};
  for (const [key, value] of captured.headers) {
    if (EVIDENCE_HEADERS.has(key)) {
      headers[key] = redactHeaderValue(key, value);
    }
  }
  return {
    kind: 'http-request',
    method,
    path,
    ...(requestBody !== undefined
      ? { request: { body: clip(redactSecrets(requestBody), 200) } }
      : {}),
    response: {
      status: captured.status,
      headers,
      body: clip(redactSecrets(captured.body), 400),
    },
  };
}
