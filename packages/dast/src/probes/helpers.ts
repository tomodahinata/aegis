/** Shared helpers for authoring probes — build a finding, manipulate URLs, reuse the docs convention. */

import { type Confidence, docsUrlFor, type HttpExchange, type Severity } from '@aegiskit/scanner';
import type { CapturedResponse } from '../http/evidence';
import type { DynamicFinding, ProbeContext, ProbeMeta } from './types';

export { docsUrlFor };

export interface FindingParts {
  readonly message: string;
  readonly confidence: Confidence;
  readonly evidence: string;
  readonly remediation: string;
  readonly target: HttpExchange;
  /** Override the probe's default severity for this finding (e.g. missing CSP=HIGH vs Referrer=LOW). */
  readonly severity?: Severity;
}

/** Assemble a `DynamicFinding`, filling identity/owasp/docs/routePath from the probe + context. */
export function dynamicFinding(
  meta: ProbeMeta,
  ctx: ProbeContext,
  parts: FindingParts,
): DynamicFinding {
  return {
    probeId: meta.id,
    severity: parts.severity ?? meta.severity,
    confidence: parts.confidence,
    message: parts.message,
    owasp: meta.owasp,
    docsUrl: meta.docsUrl,
    remediation: parts.remediation,
    routePath: ctx.target.path,
    ...(ctx.target.sourceFile !== undefined ? { sourceFile: ctx.target.sourceFile } : {}),
    evidence: parts.evidence,
    target: parts.target,
  };
}

/** Add or replace a query parameter on a URL. */
export function withQuery(url: string, param: string, value: string): string {
  const next = new URL(url);
  next.searchParams.set(param, value);
  return next.toString();
}

/** The path + query of a URL, for `HttpExchange.path`. */
export function pathOf(url: string): string {
  const parsed = new URL(url);
  return parsed.pathname + parsed.search;
}

/** An unguessable, low-collision marker for reflection/canary detection (e.g. `aeg1a2b3c4d`). */
export function randomMarker(): string {
  const bytes = new Uint8Array(4);
  globalThis.crypto.getRandomValues(bytes);
  return `aeg${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/** Send a GET and return the captured response, or `undefined` on any denial/error (fail secure). */
export async function getOk(ctx: ProbeContext, url: string): Promise<CapturedResponse | undefined> {
  const result = await ctx.http.send({ method: 'GET', url });
  return result.ok ? result.response : undefined;
}

/**
 * A signature that normalizes away volatile bytes (tokens, numbers, whitespace), so two responses can
 * be compared for a *meaningful* difference (used by the SQLi boolean differential and IDOR body match).
 */
export function bodySignature(response: CapturedResponse): string {
  const normalized = response.body
    .replace(/[0-9a-f]{8,}/gi, '')
    .replace(/\d+/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return `${response.status}:${normalized.length}`;
}
