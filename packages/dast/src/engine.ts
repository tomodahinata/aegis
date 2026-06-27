/**
 * The probe engine. Resolves and confines scope (fail-fast), discovers the attack surface, runs the
 * applicable probes under the shared request gate/budget, collects findings, and correlates them with a
 * prior static scan. A `dry-run` builds the full request plan through a planning client that touches no
 * socket and no ledger — so `requestsSent` is provably 0.
 */

import type { ScanResult } from '@aegiskit/scanner';
import { type CanaryServer, startCanaryServer } from './canary/server';
import { type Correlation, correlate } from './correlate';
import { createHttpClient, type HttpClient } from './http/client';
import type { CapturedResponse } from './http/evidence';
import { ALL_PROBES } from './probes/registry';
import type {
  BlastRadius,
  DynamicFinding,
  IdentityConfig,
  Probe,
  ProbeContext,
  Target,
} from './probes/types';
import { type Budget, createLedger, resolveBudget } from './safety/budget';
import { type RemoteConsent, resolveScopePolicy } from './safety/consent';
import { checkScope } from './safety/scope';
import { createRequestGate } from './scheduler/scheduler';
import { discoverRoutes, targetFromUrl } from './targets/discover';

export type ProbeMode = 'passive' | 'active' | 'dry-run';

export interface ProbeOptions {
  /** Target origin, e.g. `http://localhost:3000`. Loopback unless `consent` unlocks a remote host. */
  readonly origin: string;
  /** Explicit URLs to probe (in addition to discovered routes). */
  readonly targets?: readonly string[];
  /** Project root to discover App-Router `route.ts` files from. */
  readonly cwd?: string;
  readonly mode?: ProbeMode;
  readonly probes?: readonly Probe[];
  readonly budget?: Partial<Budget>;
  /** Required for a non-loopback origin. */
  readonly consent?: RemoteConsent;
  /** Credentials for the active authz probes. */
  readonly identities?: IdentityConfig;
  /** A prior static scan to correlate against (confirm-exploitable). */
  readonly staticResult?: ScanResult;
  /** External cancel signal, combined with the deadline. */
  readonly signal?: AbortSignal;
  /** Injectable fetch for tests. */
  readonly fetchImpl?: typeof fetch;
}

export interface PlannedRequest {
  readonly probeId: string;
  readonly method: string;
  readonly url: string;
  readonly blastRadius: BlastRadius;
}

export interface ProbeResult {
  /** Unified findings (static — some confirmed — plus dynamic), ready for any reporter. */
  readonly findings: ReturnType<typeof correlate>['findings'];
  readonly dynamicFindings: readonly DynamicFinding[];
  readonly correlations: readonly Correlation[];
  /** Populated in dry-run: every request that WOULD be sent. Empty otherwise. */
  readonly plan: readonly PlannedRequest[];
  readonly targets: readonly Target[];
  readonly requestsSent: number;
  /** Probes that threw and were treated as inconclusive (fail-secure) — surfaced so partial coverage is never silent. */
  readonly probesFailed: number;
  readonly durationMs: number;
  readonly mode: ProbeMode;
  /** The attestation statement, when a remote run was consented — audit record. */
  readonly authorizedBy?: string;
}

const EMPTY_RESPONSE: CapturedResponse = {
  status: 0,
  headers: new Map(),
  setCookies: [],
  body: '',
  truncated: false,
  elapsedMs: 0,
};

/** A client that records the request into the dry-run plan and sends nothing. */
function planningClient(
  probeId: string,
  blastRadius: BlastRadius,
  plan: PlannedRequest[],
): HttpClient {
  return {
    sent: 0,
    send(req) {
      plan.push({ probeId, method: req.method, url: req.url, blastRadius });
      return Promise.resolve({ ok: true, response: EMPTY_RESPONSE });
    },
  };
}

/** A canary stub for dry-run — never binds a socket, never reports a hit. */
function noopCanary(): CanaryServer {
  return {
    origin: 'http://127.0.0.1:0',
    issue: () => ({ token: 'dry-run', url: 'http://127.0.0.1:0/__aegis_canary__/dry-run' }),
    awaitHit: () => Promise.resolve(false),
    close: () => Promise.resolve(),
  };
}

async function mapPool<T>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let index = 0;
  const worker = async (): Promise<void> => {
    while (index < items.length) {
      const current = index;
      index += 1;
      const item = items[current];
      if (item !== undefined) {
        await fn(item);
      }
    }
  };
  const workers = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: workers }, () => worker()));
}

function dedupe(findings: readonly DynamicFinding[]): DynamicFinding[] {
  const seen = new Set<string>();
  const out: DynamicFinding[] = [];
  for (const finding of findings) {
    const key = `${finding.probeId}::${finding.routePath}::${finding.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(finding);
    }
  }
  return out;
}

export async function probe(options: ProbeOptions): Promise<ProbeResult> {
  const started = Date.now();
  const mode = options.mode ?? 'passive';
  // Fail fast & fail closed: an out-of-scope origin throws before any target is built.
  const scope = resolveScopePolicy(options.origin, options.consent);
  const budget = resolveBudget(options.budget);
  const probes = options.probes ?? ALL_PROBES;

  const discovered: Target[] = [];
  for (const raw of options.targets ?? []) {
    try {
      discovered.push(targetFromUrl(raw, scope.origin));
    } catch {
      // skip malformed explicit targets
    }
  }
  if (options.cwd !== undefined) {
    discovered.push(...discoverRoutes(options.cwd, scope.origin));
  }
  // Confinement: a discovered URL can never widen scope.
  const targets = discovered.filter((target) => checkScope(target.url, scope).ok);

  const ledger = createLedger(budget);
  const deadline = new AbortController();
  const deadlineTimer = setTimeout(() => deadline.abort(), budget.deadlineMs);
  const signal = options.signal
    ? AbortSignal.any([deadline.signal, options.signal])
    : deadline.signal;
  const gate = createRequestGate({ budget, ledger, signal });

  const dryRun = mode === 'dry-run';
  const findings: DynamicFinding[] = [];
  const plan: PlannedRequest[] = [];
  let probesFailed = 0;
  const canary: CanaryServer = dryRun ? noopCanary() : await startCanaryServer();
  const realClient: HttpClient | undefined = dryRun
    ? undefined
    : createHttpClient({
        scope,
        gate,
        budget,
        mode: mode === 'active' ? 'active' : 'passive',
        signal,
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      });

  try {
    const tasks: Array<{ target: Target; probe: Probe }> = [];
    for (const target of targets) {
      for (const candidate of probes) {
        if (!candidate.appliesTo(target)) {
          continue;
        }
        if (candidate.meta.blastRadius === 'active' && mode !== 'active') {
          continue;
        }
        tasks.push({ target, probe: candidate });
      }
    }

    await mapPool(tasks, budget.concurrency, async ({ target, probe: candidate }) => {
      const ctx: ProbeContext = {
        origin: scope.origin,
        target,
        http: realClient ?? planningClient(candidate.meta.id, candidate.meta.blastRadius, plan),
        canary,
        ...(options.identities ? { identities: options.identities } : {}),
        report: (finding) => {
          findings.push(finding);
        },
      };
      try {
        await candidate.run(ctx);
      } catch {
        // A probe that throws is inconclusive — never a pass (fail secure). Count it so partial
        // coverage is observable rather than silently hidden behind a clean-looking report.
        probesFailed += 1;
      }
    });

    const deduped = dedupe(findings);
    const merged = correlate(options.staticResult, deduped, scope.origin);
    return {
      findings: merged.findings,
      dynamicFindings: deduped,
      correlations: merged.correlations,
      plan,
      targets,
      requestsSent: ledger.sent,
      probesFailed,
      durationMs: Date.now() - started,
      mode,
      ...(options.consent?.ack ? { authorizedBy: options.consent.ack.statement } : {}),
    };
  } finally {
    clearTimeout(deadlineTimer);
    // Teardown is best-effort: it must never throw out of a completed run and flip a clean result
    // into an internal-error exit. The canary is loopback-only; the OS reclaims the socket on exit.
    try {
      await canary.close();
    } catch {
      // ignore — the run's findings are already computed and returned above
    }
  }
}
