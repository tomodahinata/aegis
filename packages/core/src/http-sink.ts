/**
 * `createHttpSink` — a `SecuritySink` that ships events to an ingestion endpoint.
 *
 * It is designed to be invisible to the request it observes: `emit()` is synchronous and
 * total (never throws, never blocks), the in-memory queue is hard-bounded (drop-oldest on
 * overflow, counted), delivery is micro-batched + retried with jittered backoff, and each
 * batch is HMAC-signed so the endpoint can authenticate it. Every event carries a stable
 * idempotency `id` (minted once, reused across retries) so at-least-once delivery dedupes to
 * effectively-once at the store. Edge-safe: Web Crypto + fetch only, no `node:`/DOM.
 */

import type { SecurityEvent, SecuritySink } from './events';
import { bytesToBase64Url, randomBase64Url } from './internal/encoding';

export type SinkTimer = ReturnType<typeof setTimeout> | number;

export interface SinkScheduler {
  setTimeout(handler: () => void, ms: number): SinkTimer;
  clearTimeout(timer: SinkTimer): void;
}

export interface HttpSinkOptions {
  /** Ingestion endpoint. Batches are POSTed here as `application/json`. */
  readonly endpoint: string;
  /**
   * Shared secret for HMAC-SHA-256 batch signing. Resolve it from your typed env boundary;
   * a missing/empty secret throws at construction (never ship unauthenticated events).
   */
  readonly secret: string;
  /** Flush when this many events are queued. Default 20. */
  readonly maxBatchSize?: number;
  /** Flush at most this often (ms) while events are queued. Default 2000. */
  readonly flushIntervalMs?: number;
  /** Hard cap on the in-memory queue; on overflow the OLDEST event is dropped. Default 1000. */
  readonly maxQueueSize?: number;
  /** Per-attempt deadline via `AbortSignal.timeout`. Default 3000. */
  readonly requestTimeoutMs?: number;
  /** Retry attempts after the first try (total tries = retries + 1). Default 3. */
  readonly maxRetries?: number;
  /** Base backoff (ms). Default 200. */
  readonly baseDelayMs?: number;
  /** Backoff ceiling (ms). Default 5000. */
  readonly maxDelayMs?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly scheduler?: SinkScheduler;
  /** Called when events are dropped on overflow: `(droppedTotal, emittedTotal)`. */
  readonly onDrop?: (droppedTotal: number, emittedTotal: number) => void;
  /** Called when a batch is permanently abandoned (after retries / on a 4xx). */
  readonly onError?: (error: unknown, batchSize: number) => void;
}

export interface HttpSinkStats {
  readonly queued: number;
  readonly dropped: number;
  readonly inFlight: number;
}

export interface HttpSink extends SecuritySink {
  /** Force a flush and await in-flight delivery (shutdown / tests). */
  flush(): Promise<void>;
  /** Stop the timer and flush once. Idempotent. */
  close(): Promise<void>;
  stats(): HttpSinkStats;
}

/** A queued event carries a stable idempotency id. This is what the ingestion endpoint receives. */
export type WireEvent = SecurityEvent & { readonly id: string };

// Reference the Web Crypto key type structurally (the `CryptoKey` name needs the DOM lib,
// which `@aegiskit/core` deliberately omits to stay edge/runtime-agnostic).
type SigningKeyPromise = ReturnType<typeof globalThis.crypto.subtle.importKey>;

function defaultScheduler(): SinkScheduler {
  return {
    setTimeout: (handler, ms) => {
      const timer = setTimeout(handler, ms);
      // Don't let the heartbeat keep a Node process alive (no-op on edge/browser).
      (timer as { unref?: () => void }).unref?.();
      return timer;
    },
    clearTimeout: (timer) => {
      clearTimeout(timer as Parameters<typeof clearTimeout>[0]);
    },
  };
}

export function createHttpSink(options: HttpSinkOptions): HttpSink {
  if (!options.secret) {
    throw new Error(
      'createHttpSink: a non-empty `secret` is required (it HMAC-signs every batch).',
    );
  }
  const { endpoint, secret, onDrop, onError } = options;
  const maxBatchSize = options.maxBatchSize ?? 20;
  const flushIntervalMs = options.flushIntervalMs ?? 2000;
  const maxQueueSize = options.maxQueueSize ?? 1000;
  const requestTimeoutMs = options.requestTimeoutMs ?? 3000;
  const maxRetries = options.maxRetries ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 200;
  const maxDelayMs = options.maxDelayMs ?? 5000;
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  const now = options.now ?? Date.now;
  const random = options.random ?? Math.random;
  const scheduler = options.scheduler ?? defaultScheduler();

  const queue: WireEvent[] = [];
  let dropped = 0;
  let emitted = 0;
  let inFlight = 0;
  let timer: SinkTimer | undefined;
  let pumping: Promise<void> | null = null;
  let keyPromise: SigningKeyPromise | undefined;

  function signingKey(): SigningKeyPromise {
    keyPromise ??= globalThis.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    return keyPromise;
  }

  async function sign(timestamp: string, body: string): Promise<string> {
    const mac = await globalThis.crypto.subtle.sign(
      'HMAC',
      await signingKey(),
      new TextEncoder().encode(`${timestamp}.${body}`),
    );
    return `sha256=${bytesToBase64Url(new Uint8Array(mac))}`;
  }

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      scheduler.setTimeout(resolve, ms);
    });
  }

  // Full-jitter capped exponential backoff (jitter avoids synchronized retries across instances).
  function backoff(attempt: number): number {
    return random() * Math.min(baseDelayMs * 2 ** attempt, maxDelayMs);
  }

  async function deliver(batch: WireEvent[]): Promise<void> {
    const body = JSON.stringify({ v: 1, events: batch });
    let lastError: unknown = new Error('Aegis ingest delivery failed');
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const timestamp = String(now());
        const response = await doFetch(endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-aegis-signature': await sign(timestamp, body),
            'x-aegis-timestamp': timestamp,
          },
          body,
          signal: AbortSignal.timeout(requestTimeoutMs),
        });
        if (response.ok) {
          return;
        }
        // 4xx (except 429) is permanent — don't hammer an endpoint that is rejecting us.
        if (response.status >= 400 && response.status < 500 && response.status !== 429) {
          onError?.(new Error(`Aegis ingest endpoint returned ${response.status}`), batch.length);
          return;
        }
        lastError = new Error(`Aegis ingest endpoint returned ${response.status}`);
      } catch (error) {
        lastError = error; // network error / timeout abort → retry
      }
      if (attempt < maxRetries) {
        await sleep(backoff(attempt));
      }
    }
    onError?.(lastError, batch.length);
  }

  function pump(): Promise<void> {
    pumping ??= (async () => {
      while (queue.length > 0) {
        const batch = queue.splice(0, maxBatchSize);
        inFlight += batch.length;
        try {
          await deliver(batch);
        } finally {
          inFlight -= batch.length;
        }
      }
    })().finally(() => {
      pumping = null;
    });
    return pumping;
  }

  function arm(): void {
    if (timer !== undefined) {
      return;
    }
    timer = scheduler.setTimeout(() => {
      timer = undefined;
      void pump();
      if (queue.length > 0) {
        arm();
      }
    }, flushIntervalMs);
  }

  return {
    emit(event: SecurityEvent): void {
      try {
        emitted += 1;
        queue.push({ ...event, id: randomBase64Url(16) } as WireEvent);
        if (queue.length > maxQueueSize) {
          queue.shift();
          dropped += 1;
          onDrop?.(dropped, emitted);
        }
        if (queue.length >= maxBatchSize) {
          void pump();
        } else {
          arm();
        }
      } catch {
        // A sink must never be able to break the request it observes.
      }
    },
    flush(): Promise<void> {
      return pump();
    },
    async close(): Promise<void> {
      if (timer !== undefined) {
        scheduler.clearTimeout(timer);
        timer = undefined;
      }
      await pump();
    },
    stats(): HttpSinkStats {
      return { queued: queue.length, dropped, inFlight };
    },
  };
}
