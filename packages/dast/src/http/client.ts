/**
 * The single network choke point. Every probe request flows through `send`, where all five safety
 * gates converge: scope confinement, blast-radius (passive ⇒ safe methods only), the request budget
 * (via the gate/ledger), a per-request timeout combined with the global deadline, and `redirect:
 * 'manual'` so a hostile redirect can never bounce a probe off-origin. A probe receives only this
 * pre-confined client — it can neither widen scope nor exceed the budget.
 */

import type { Budget } from '../safety/budget';
import { checkScope, type ScopeDenyReason, type ScopePolicy } from '../safety/scope';
import type { RequestGate } from '../scheduler/scheduler';
import { type CapturedResponse, captureResponse } from './evidence';

export type SafeMethod = 'GET' | 'HEAD' | 'OPTIONS' | 'TRACE';
export type Method = SafeMethod | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

// Idempotent, side-effect-free methods allowed even in passive mode (TRACE included for XST detection).
const SAFE_METHODS: ReadonlySet<Method> = new Set<Method>(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export interface SendRequest {
  readonly method: Method;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
}

export type SendResult =
  | { readonly ok: true; readonly response: CapturedResponse }
  | {
      readonly ok: false;
      readonly denied: ScopeDenyReason | 'method-not-allowed-in-passive' | 'budget' | 'deadline';
    }
  | { readonly ok: false; readonly error: 'timeout' | 'network'; readonly message: string };

export interface HttpClient {
  send(req: SendRequest): Promise<SendResult>;
  /** Requests this client actually issued (post-gate) — surfaced into the ProbeResult. */
  readonly sent: number;
}

export interface HttpClientOptions {
  readonly scope: ScopePolicy;
  readonly gate: RequestGate;
  readonly budget: Budget;
  readonly mode: 'passive' | 'active';
  /** Global deadline / cancel signal, combined with each request's timeout. */
  readonly signal: AbortSignal;
  /** Injectable fetch for tests (defaults to global fetch). */
  readonly fetchImpl?: typeof fetch;
  readonly bodyCapBytes?: number;
}

function classifyError(error: unknown): { error: 'timeout' | 'network'; message: string } {
  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);
  return name === 'TimeoutError' || name === 'AbortError'
    ? { error: 'timeout', message }
    : { error: 'network', message };
}

export function createHttpClient(opts: HttpClientOptions): HttpClient {
  const doFetch = opts.fetchImpl ?? fetch;
  let sent = 0;

  return {
    get sent(): number {
      return sent;
    },
    async send(req: SendRequest): Promise<SendResult> {
      const decision = checkScope(req.url, opts.scope);
      if (!decision.ok) {
        return { ok: false, denied: decision.reason };
      }
      if (opts.mode === 'passive' && !SAFE_METHODS.has(req.method)) {
        return { ok: false, denied: 'method-not-allowed-in-passive' };
      }
      const grant = await opts.gate.acquire();
      if (!grant.ok) {
        return { ok: false, denied: grant.denied };
      }
      // Combine the global deadline with a per-request timeout, with explicit cleanup so no timer lingers.
      const controller = new AbortController();
      const onAbort = (): void => controller.abort();
      if (opts.signal.aborted) {
        controller.abort();
      } else {
        opts.signal.addEventListener('abort', onAbort, { once: true });
      }
      const timer = setTimeout(() => controller.abort(), opts.budget.perRequestTimeoutMs);
      const startedAt = Date.now();
      try {
        sent += 1;
        const response = await doFetch(req.url, {
          method: req.method,
          redirect: 'manual',
          signal: controller.signal,
          ...(req.headers ? { headers: req.headers } : {}),
          ...(req.body !== undefined ? { body: req.body } : {}),
        });
        const captured = await captureResponse(response, Date.now() - startedAt, opts.bodyCapBytes);
        return { ok: true, response: captured };
      } catch (error) {
        return { ok: false, ...classifyError(error) };
      } finally {
        clearTimeout(timer);
        opts.signal.removeEventListener('abort', onAbort);
        grant.release();
      }
    },
  };
}
