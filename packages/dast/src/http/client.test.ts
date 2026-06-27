import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLedger, resolveBudget } from '../safety/budget';
import type { ScopePolicy } from '../safety/scope';
import { createRequestGate } from '../scheduler/scheduler';
import { type MockTarget, startMockTarget } from '../testing/mock-target';
import { createHttpClient, type HttpClient } from './client';

let mock: MockTarget;
beforeAll(async () => {
  mock = await startMockTarget();
});
afterAll(async () => {
  await mock.close();
});

function clientFor(originHost: string, mode: 'passive' | 'active' = 'passive'): HttpClient {
  const budget = resolveBudget({ minIntervalMs: 0, perRequestTimeoutMs: 1000 });
  const ledger = createLedger(budget);
  const scope: ScopePolicy = {
    origin: mock.origin,
    originHost,
    remoteConsented: false,
    allowHosts: new Set([originHost]),
  };
  const gate = createRequestGate({ budget, ledger });
  return createHttpClient({ scope, gate, budget, mode, signal: new AbortController().signal });
}

describe('ScopedHttpClient', () => {
  it('denies an off-scope URL without sending a request', async () => {
    const client = clientFor('127.0.0.1');
    const result = await client.send({ method: 'GET', url: 'https://evil.example/x' });
    expect(result).toEqual({ ok: false, denied: 'non-loopback-without-consent' });
    expect(client.sent).toBe(0);
  });

  it('refuses a state-changing method in passive mode', async () => {
    const client = clientFor('127.0.0.1');
    const result = await client.send({ method: 'POST', url: `${mock.origin}/headers-missing` });
    expect(result).toEqual({ ok: false, denied: 'method-not-allowed-in-passive' });
    expect(client.sent).toBe(0);
  });

  it('captures a redirect Location WITHOUT following it', async () => {
    const client = clientFor('127.0.0.1');
    const result = await client.send({
      method: 'GET',
      url: `${mock.origin}/redirect-open?next=https://evil.example/x`,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      // Status stays 3xx (not 200) because the redirect was captured, not followed.
      expect(result.response.status).toBe(302);
      expect(result.response.location).toBe('https://evil.example/x');
    }
  });
});
