import fc from 'fast-check';
import { describe, expect, it, vi } from 'vitest';
import type { SecurityEvent } from './events';
import { createHttpSink, type SinkScheduler, type SinkTimer } from './http-sink';

const SECRET = 'x'.repeat(32);

function event(i = 0): SecurityEvent {
  return {
    type: 'rate_limit_block',
    at: 1_700_000_000_000 + i,
    key: `k${i}`,
    rule: 'ip',
    limit: 60,
  };
}

/** Records timers but never fires them — so nothing flushes until we ask. */
function manualScheduler(): SinkScheduler & { fire(): void; pending(): number } {
  const tasks = new Map<number, () => void>();
  let id = 0;
  return {
    setTimeout: (fn) => {
      const t = ++id;
      tasks.set(t, fn);
      return t;
    },
    clearTimeout: (t) => {
      tasks.delete(t as number);
    },
    fire: () => {
      const fns = [...tasks.values()];
      tasks.clear();
      for (const fn of fns) {
        fn();
      }
    },
    pending: () => tasks.size,
  };
}

/** Fires timers on the next microtask — retry sleeps resolve automatically. */
function autoScheduler(): SinkScheduler {
  return {
    setTimeout: (fn) => {
      queueMicrotask(fn);
      return 0 as SinkTimer;
    },
    clearTimeout: () => {},
  };
}

function fetchStub(responses: Array<{ status: number } | 'throw'>) {
  const calls: Array<{ body: string; headers: Headers }> = [];
  let i = 0;
  const fn = ((_url: string | URL | Request, init?: RequestInit) => {
    calls.push({ body: String(init?.body), headers: new Headers(init?.headers) });
    const r = responses[Math.min(i, responses.length - 1)] ?? { status: 200 };
    i += 1;
    if (r === 'throw') {
      return Promise.reject(new Error('network down'));
    }
    return Promise.resolve(new Response(null, { status: r.status }));
  }) as typeof fetch;
  return { fn, calls };
}

async function expectedMac(message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  let binary = '';
  for (const b of new Uint8Array(mac)) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

describe('createHttpSink', () => {
  it('throws at construction without a secret', () => {
    expect(() => createHttpSink({ endpoint: 'https://x', secret: '' })).toThrow();
  });

  it('does not POST below the batch size until flushed', async () => {
    const { fn, calls } = fetchStub([{ status: 200 }]);
    const sink = createHttpSink({
      endpoint: 'https://x',
      secret: SECRET,
      maxBatchSize: 5,
      fetch: fn,
      scheduler: manualScheduler(),
    });
    sink.emit(event());
    expect(calls).toHaveLength(0);
    await sink.flush();
    expect(calls).toHaveLength(1);
  });

  it('signs the batch (HMAC over timestamp.body round-trips)', async () => {
    const { fn, calls } = fetchStub([{ status: 200 }]);
    const sink = createHttpSink({
      endpoint: 'https://x',
      secret: SECRET,
      maxBatchSize: 1,
      fetch: fn,
      scheduler: autoScheduler(),
    });
    sink.emit(event());
    await sink.flush();
    const first = calls[0];
    if (!first) {
      throw new Error('expected one POST');
    }
    const ts = first.headers.get('x-aegis-timestamp');
    const sig = first.headers.get('x-aegis-signature');
    expect(sig).toBe(`sha256=${await expectedMac(`${ts}.${first.body}`)}`);
  });

  it('retries 5xx then succeeds, reusing the same idempotency ids', async () => {
    const { fn, calls } = fetchStub([{ status: 500 }, { status: 200 }]);
    const sink = createHttpSink({
      endpoint: 'https://x',
      secret: SECRET,
      maxBatchSize: 1,
      baseDelayMs: 1,
      fetch: fn,
      scheduler: autoScheduler(),
    });
    sink.emit(event());
    await sink.flush();
    expect(calls).toHaveLength(2);
    const ids = (body: string) =>
      (JSON.parse(body) as { events: { id: string }[] }).events.map((e) => e.id);
    expect(ids(calls[0]?.body ?? '')).toEqual(ids(calls[1]?.body ?? ''));
  });

  it('does not retry a permanent 4xx, and reports it once', async () => {
    const onError = vi.fn();
    const { fn, calls } = fetchStub([{ status: 400 }]);
    const sink = createHttpSink({
      endpoint: 'https://x',
      secret: SECRET,
      maxBatchSize: 1,
      fetch: fn,
      scheduler: autoScheduler(),
      onError,
    });
    sink.emit(event());
    await sink.flush();
    expect(calls).toHaveLength(1);
    expect(onError).toHaveBeenCalledOnce();
  });

  it('flush never rejects even when fetch throws', async () => {
    const sink = createHttpSink({
      endpoint: 'https://x',
      secret: SECRET,
      maxBatchSize: 1,
      maxRetries: 0,
      fetch: (() => Promise.reject(new Error('boom'))) as typeof fetch,
      scheduler: autoScheduler(),
    });
    sink.emit(event());
    await expect(sink.flush()).resolves.toBeUndefined();
  });

  it('property: queue stays bounded and no event is lost without a drop count', () => {
    const throwFetch = (() => {
      throw new Error('should not deliver in this test');
    }) as typeof fetch;
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 40 }),
        fc.integer({ min: 0, max: 200 }),
        (maxQueueSize, count) => {
          const sink = createHttpSink({
            endpoint: 'https://x',
            secret: SECRET,
            maxQueueSize,
            maxBatchSize: 100_000, // never size-flush
            fetch: throwFetch,
            scheduler: manualScheduler(), // never time-flush
          });
          for (let i = 0; i < count; i++) {
            sink.emit(event(i));
          }
          const stats = sink.stats();
          expect(stats.queued).toBeLessThanOrEqual(maxQueueSize);
          expect(count).toBe(stats.queued + stats.dropped); // every event accounted for
        },
      ),
    );
  });
});
