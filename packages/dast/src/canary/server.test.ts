import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type CanaryServer, startCanaryServer } from './server';

let canary: CanaryServer;
beforeAll(async () => {
  canary = await startCanaryServer();
});
afterAll(async () => {
  await canary.close();
});

describe('canary server', () => {
  it('binds to loopback on an ephemeral port', () => {
    expect(canary.origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it('mints unguessable tokens', () => {
    const a = canary.issue();
    const b = canary.issue();
    expect(a.token).not.toBe(b.token);
    expect(a.token).toMatch(/^[a-f0-9]{32}$/);
  });

  it('resolves true when the token URL is hit', async () => {
    const token = canary.issue();
    const waiting = canary.awaitHit(token.token, 1000);
    await fetch(token.url);
    expect(await waiting).toBe(true);
  });

  it('resolves false on timeout (no hit ⇒ no finding)', async () => {
    const token = canary.issue();
    expect(await canary.awaitHit(token.token, 50)).toBe(false);
  });

  it('close() is idempotent — a benign already-closed teardown resolves, never rejects', async () => {
    // A rejecting teardown awaited in the engine's finally would discard a completed run's findings
    // and flip a clean scan to an internal-error exit. A second close must resolve.
    const server = await startCanaryServer();
    await server.close();
    await expect(server.close()).resolves.toBeUndefined();
  });
});
