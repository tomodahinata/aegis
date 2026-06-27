import { createHttpSink, type SinkScheduler } from '@aegiskit/core';
import { describe, expect, it } from 'vitest';
import { verifyBatchSignature } from './signature';

const SECRET = 's'.repeat(32);
const NOW = 1_700_000_000_000;
const now = () => NOW;

async function sign(secret: string, timestamp: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${timestamp}.${body}`),
  );
  let binary = '';
  for (const b of new Uint8Array(mac)) {
    binary += String.fromCharCode(b);
  }
  const b64 = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
  return `sha256=${b64}`;
}

describe('verifyBatchSignature', () => {
  const ts = String(NOW);
  const body = '{"v":1,"events":[]}';

  it('accepts a valid fresh signature', async () => {
    const header = await sign(SECRET, ts, body);
    expect(await verifyBatchSignature(SECRET, body, ts, header, { now })).toBe(true);
  });

  it('rejects a tampered body, a wrong secret, and a tampered signature', async () => {
    const header = await sign(SECRET, ts, body);
    expect(await verifyBatchSignature(SECRET, `${body} `, ts, header, { now })).toBe(false);
    expect(await verifyBatchSignature('z'.repeat(32), body, ts, header, { now })).toBe(false);
    expect(await verifyBatchSignature(SECRET, body, ts, `${header}AA`, { now })).toBe(false);
  });

  it('rejects a stale timestamp (replay defense)', async () => {
    const staleTs = String(NOW - 10 * 60 * 1000);
    const header = await sign(SECRET, staleTs, body);
    expect(await verifyBatchSignature(SECRET, body, staleTs, header, { now })).toBe(false);
  });

  it('rejects malformed input fail-secure', async () => {
    expect(await verifyBatchSignature(SECRET, body, 'not-a-number', 'sha256=x', { now })).toBe(
      false,
    );
    expect(await verifyBatchSignature(SECRET, body, ts, 'sha256=!!!not-base64!!!', { now })).toBe(
      false,
    );
  });

  it('verifies a signature produced by createHttpSink (signer↔verifier interop)', async () => {
    const captured: RequestInit[] = [];
    const scheduler: SinkScheduler = {
      setTimeout: (fn) => {
        queueMicrotask(fn);
        return 0;
      },
      clearTimeout: () => {},
    };
    const sink = createHttpSink({
      endpoint: 'https://ingest.example',
      secret: SECRET,
      maxBatchSize: 1,
      now,
      scheduler,
      fetch: ((_url: string | URL | Request, init?: RequestInit) => {
        if (init) {
          captured.push(init);
        }
        return Promise.resolve(new Response(null, { status: 200 }));
      }) as typeof fetch,
    });
    sink.emit({ type: 'csrf_block', at: NOW, reason: 'host-mismatch' });
    await sink.flush();

    const init = captured[0];
    if (!init) {
      throw new Error('expected one POST');
    }
    const headers = new Headers(init.headers);
    const ok = await verifyBatchSignature(
      SECRET,
      String(init.body),
      headers.get('x-aegis-timestamp') ?? '',
      headers.get('x-aegis-signature') ?? '',
      { now },
    );
    expect(ok).toBe(true);
  });
});
