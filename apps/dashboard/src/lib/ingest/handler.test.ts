import { createMemoryEventStore } from '@aegiskit/observability';
import { describe, expect, it } from 'vitest';
import { ingestEvents } from './handler';

const SECRET = 's'.repeat(40);
const NOW = 1_700_000_000_000;
const now = () => NOW;

async function sign(body: string, timestamp: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(SECRET),
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
  return `sha256=${btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')}`;
}

const body = JSON.stringify({
  events: [
    { type: 'origin_block', id: 'a', at: NOW, origin: 'https://evil', reason: 'host-mismatch' },
  ],
});

describe('ingestEvents (the critical verifier seam)', () => {
  it('accepts a valid signed batch and stores it (204)', async () => {
    const store = createMemoryEventStore();
    const timestamp = String(NOW);
    const result = await ingestEvents({
      rawBody: body,
      timestamp,
      signature: await sign(body, timestamp),
      secret: SECRET,
      store,
      now,
    });
    expect(result).toEqual({ status: 204, accepted: 1 });
    expect(await store.query()).toHaveLength(1);
  });

  it('rejects a bad or missing signature with 401 (and stores nothing)', async () => {
    const store = createMemoryEventStore();
    const timestamp = String(NOW);
    expect(
      (
        await ingestEvents({
          rawBody: body,
          timestamp,
          signature: 'sha256=bad',
          secret: SECRET,
          store,
          now,
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await ingestEvents({
          rawBody: body,
          timestamp: null,
          signature: null,
          secret: SECRET,
          store,
          now,
        })
      ).status,
    ).toBe(401);
    expect(await store.query()).toHaveLength(0);
  });

  it('rejects malformed JSON and schema-invalid bodies with 400', async () => {
    const store = createMemoryEventStore();
    const timestamp = String(NOW);
    const garbage = 'not json';
    expect(
      (
        await ingestEvents({
          rawBody: garbage,
          timestamp,
          signature: await sign(garbage, timestamp),
          secret: SECRET,
          store,
          now,
        })
      ).status,
    ).toBe(400);
    const invalid = JSON.stringify({ events: [{ type: 'nope' }] });
    expect(
      (
        await ingestEvents({
          rawBody: invalid,
          timestamp,
          signature: await sign(invalid, timestamp),
          secret: SECRET,
          store,
          now,
        })
      ).status,
    ).toBe(400);
  });
});
