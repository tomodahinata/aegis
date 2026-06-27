/**
 * The probe contract — deliberately isomorphic to the scanner's `Rule`, so the static and dynamic
 * engines read as the same idea in two dimensions. A probe declares its blast radius (the engine
 * refuses to run `active` probes unless explicitly enabled) and receives a pre-confined `ctx.http`,
 * so it can neither widen scope nor exceed the budget.
 */

import type { Confidence, HttpExchange, Severity } from '@aegiskit/scanner';
import type { CanaryRegistry } from '../canary/server';
import type { HttpClient } from '../http/client';

/** A probe's maximum side effect. `passive`: read-only/idempotent. `active`: may send non-GET/auth probes. */
export type BlastRadius = 'passive' | 'active';

/** One route (or explicit URL) the engine probes. */
export interface Target {
  readonly origin: string;
  /** Route pattern, e.g. `/api/users/[id]` — the correlation join key. */
  readonly path: string;
  /** Concrete URL with dynamic segments filled, e.g. `http://localhost:3000/api/users/1`. */
  readonly url: string;
  /** Exported HTTP handlers, e.g. `GET`, `POST`. */
  readonly methods: ReadonlySet<string>;
  /** Absolute path of the `route.ts` this came from, when discovered statically (for correlation). */
  readonly sourceFile?: string;
}

export interface ProbeMeta {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly owasp: string;
  readonly blastRadius: BlastRadius;
  readonly docsUrl: string;
}

/** A finding produced at runtime; carries the redacted HTTP exchange that confirmed it. */
export interface DynamicFinding {
  readonly probeId: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly message: string;
  readonly owasp: string;
  readonly docsUrl: string;
  readonly remediation: string;
  /** Route pattern this concerns — the join key for correlation with static findings. */
  readonly routePath: string;
  readonly sourceFile?: string;
  /** Stable detection descriptor (NOT the random marker/token), for fingerprint stability. */
  readonly evidence: string;
  readonly target: HttpExchange;
}

export type IdentityAuth =
  | { readonly kind: 'cookie'; readonly cookie: string }
  | { readonly kind: 'bearer'; readonly token: string }
  | { readonly kind: 'header'; readonly name: string; readonly value: string };

export interface Identity {
  readonly label: string;
  readonly auth: IdentityAuth;
  /** Object URLs (paths) this identity legitimately owns — IDOR probe targets. */
  readonly ownsObjectAt?: readonly string[];
}

export interface IdentityConfig {
  /** ≥2 distinct principals for IDOR; ≥1 for auth-required. */
  readonly identities: readonly Identity[];
  /** Route patterns that SHOULD require authentication (operator-marked). */
  readonly protectedPaths?: readonly string[];
}

export interface ProbeContext {
  readonly origin: string;
  readonly target: Target;
  readonly http: HttpClient;
  readonly canary: CanaryRegistry;
  /** Present only in `--active` mode with configured identities. */
  readonly identities?: IdentityConfig;
  report(finding: DynamicFinding): void;
}

export interface Probe {
  readonly meta: ProbeMeta;
  appliesTo(target: Target): boolean;
  run(ctx: ProbeContext): Promise<void>;
}
