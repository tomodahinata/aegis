import { describe, expect, it } from 'vitest';
import { type SessionPayload, signSessionToken, verifySessionToken } from './session';

const SECRET = 's'.repeat(40);
const NOW = 1_700_000_000_000;
const payload: SessionPayload = {
  sub: 'admin',
  iat: Math.floor(NOW / 1000),
  exp: Math.floor(NOW / 1000) + 3600,
};

describe('session token', () => {
  it('round-trips a valid session', async () => {
    const token = await signSessionToken(payload, SECRET);
    expect(await verifySessionToken(token, SECRET, NOW)).toEqual({ ok: true, payload });
  });

  it('rejects a wrong secret or a tampered token', async () => {
    const token = await signSessionToken(payload, SECRET);
    expect((await verifySessionToken(token, 'z'.repeat(40), NOW)).ok).toBe(false);
    expect((await verifySessionToken(`${token}x`, SECRET, NOW)).ok).toBe(false);
  });

  it('rejects an expired session', async () => {
    const token = await signSessionToken(payload, SECRET);
    expect(await verifySessionToken(token, SECRET, NOW + 2 * 3600 * 1000)).toEqual({
      ok: false,
      reason: 'expired',
    });
  });
});
