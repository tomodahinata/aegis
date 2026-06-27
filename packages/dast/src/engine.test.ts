import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type ProbeOptions, probe } from './engine';
import {
  authRequired,
  cookieFlags,
  errorDisclosure,
  idor,
  missingRateLimit,
  openRedirect,
  reflectedXss,
  securityHeaders,
  sqlInjection,
  ssrf,
} from './probes/registry';
import type { DynamicFinding, IdentityConfig, Probe } from './probes/types';
import { type MockTarget, startMockTarget } from './testing/mock-target';

let mock: MockTarget;
beforeAll(async () => {
  mock = await startMockTarget();
});
afterAll(async () => {
  await mock.close();
});

const FAST = { minIntervalMs: 0, perRequestTimeoutMs: 2000, deadlineMs: 20_000 };

async function run(
  path: string,
  p: Probe,
  extra: Partial<ProbeOptions> = {},
): Promise<readonly DynamicFinding[]> {
  const result = await probe({
    origin: mock.origin,
    targets: [`${mock.origin}${path}`],
    probes: [p],
    budget: FAST,
    ...extra,
  });
  return result.dynamicFindings;
}

const fires = (findings: readonly DynamicFinding[], id: string): boolean =>
  findings.some((f) => f.probeId === id);

describe('probe matrix — fires on vulnerable, silent on safe (the DAST gate)', () => {
  const cases: ReadonlyArray<readonly [Probe, string, string, string]> = [
    [securityHeaders, 'dast/security-headers', '/headers-missing', '/headers-present'],
    [cookieFlags, 'dast/cookie-flags', '/cookie-insecure', '/cookie-secure'],
    [errorDisclosure, 'dast/error-disclosure', '/error-stack', '/error-generic'],
    [openRedirect, 'dast/open-redirect', '/redirect-open', '/redirect-safe'],
    [reflectedXss, 'dast/reflected-xss', '/xss-reflect', '/xss-escaped'],
    [sqlInjection, 'dast/sql-injection', '/sqli-error', '/sqli-parameterized'],
    [sqlInjection, 'dast/sql-injection', '/sqli-boolean', '/sqli-parameterized'],
    [ssrf, 'dast/ssrf', '/ssrf-fetch', '/ssrf-blocked'],
    [missingRateLimit, 'dast/missing-rate-limit', '/noratelimit', '/ratelimited'],
  ];

  for (const [p, id, vuln, safe] of cases) {
    it(`${id}: flags ${vuln}`, async () => {
      expect(fires(await run(vuln, p), id)).toBe(true);
    });
    it(`${id}: silent on ${safe}`, async () => {
      expect(fires(await run(safe, p), id)).toBe(false);
    });
  }

  it('reflected-xss is silent when the marker is reflected into JSON (safe context)', async () => {
    expect(fires(await run('/xss-json', reflectedXss), 'dast/reflected-xss')).toBe(false);
  });
});

describe('active authz probes', () => {
  const identities: IdentityConfig = {
    identities: [
      { label: 'alice', auth: { kind: 'cookie', cookie: 'who=alice' }, ownsObjectAt: ['/obj/1'] },
      { label: 'bob', auth: { kind: 'cookie', cookie: 'who=bob' } },
    ],
    protectedPaths: ['/protected-open', '/protected-guarded'],
  };
  const active = { mode: 'active' as const, identities };

  it('auth-required flags a protected route reachable unauthenticated', async () => {
    expect(fires(await run('/protected-open', authRequired, active), 'dast/auth-required')).toBe(
      true,
    );
  });
  it('auth-required is silent on a guarded route', async () => {
    expect(fires(await run('/protected-guarded', authRequired, active), 'dast/auth-required')).toBe(
      false,
    );
  });

  it('idor flags a cross-identity object read', async () => {
    expect(fires(await run('/obj/1', idor, active), 'dast/idor')).toBe(true);
  });
  it('idor is silent on a scope-checked object', async () => {
    const scoped: IdentityConfig = {
      identities: [
        {
          label: 'alice',
          auth: { kind: 'cookie', cookie: 'who=alice' },
          ownsObjectAt: ['/obj-scoped/1'],
        },
        { label: 'bob', auth: { kind: 'cookie', cookie: 'who=bob' } },
      ],
    };
    const result = await run('/obj-scoped/1', idor, { mode: 'active', identities: scoped });
    expect(fires(result, 'dast/idor')).toBe(false);
  });

  it('does NOT run active probes in the default (passive) mode', async () => {
    const result = await probe({
      origin: mock.origin,
      targets: [`${mock.origin}/protected-open`],
      probes: [authRequired],
      budget: FAST,
      identities,
    });
    expect(result.requestsSent).toBe(0);
    expect(result.dynamicFindings).toHaveLength(0);
  });
});

describe('dry-run is inert', () => {
  it('sends zero requests but produces a plan', async () => {
    const before = mock.requestCount();
    const result = await probe({
      origin: mock.origin,
      targets: [`${mock.origin}/headers-missing`],
      probes: [securityHeaders, reflectedXss],
      mode: 'dry-run',
      budget: FAST,
    });
    expect(result.requestsSent).toBe(0);
    expect(mock.requestCount()).toBe(before); // not a single request reached the target
    expect(result.plan.length).toBeGreaterThan(0);
  });
});

describe('scope confinement at the engine level', () => {
  it('drops an off-origin target and sends nothing to it', async () => {
    const result = await probe({
      origin: mock.origin,
      targets: ['http://other-host.example/x'],
      probes: [securityHeaders],
      budget: FAST,
    });
    expect(result.targets).toHaveLength(0);
    expect(result.requestsSent).toBe(0);
  });
});
