import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '@aegiskit/scanner';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { defaultAliases, discoverFiles } from '../discover';
import { EXIT } from '../exit';
import { runCi } from './ci';
import { runDoctor } from './doctor';

/**
 * Builds a tiny project whose Client Component imports a server module *only* via the `@/`
 * alias. Without alias resolution the import edge is invisible, so `billing.ts` is never marked
 * client-reachable and the `env/secret-in-client` BLOCKER goes undetected — exactly the gap the
 * shared `defaultAliases` closes for ci/doctor.
 */
function makeAliasProject(): string {
  const root = mkdtempSync(join(tmpdir(), 'aegis-cli-'));
  const src = join(root, 'src');
  mkdirSync(src, { recursive: true });
  writeFileSync(
    join(src, 'billing.ts'),
    'export const stripeKey = process.env.STRIPE_SECRET_KEY;\n',
  );
  writeFileSync(
    join(src, 'panel.tsx'),
    "'use client';\nimport { stripeKey } from '@/billing';\nexport const Panel = () => (stripeKey ? 'on' : 'off');\n",
  );
  return root;
}

describe('alias parity (ci/doctor must gate on the same edges as scan)', () => {
  let root: string;
  beforeEach(() => {
    root = makeAliasProject();
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('defaultAliases resolves `@/` to <root>/src/ when src exists', () => {
    expect(defaultAliases(root)).toEqual({ '@/': `${join(root, 'src')}/` });
  });

  it('the alias edge surfaces the BLOCKER (regression guard for ci/doctor)', () => {
    const files = discoverFiles(root);
    const aliases = defaultAliases(root);
    const withAlias = scan({ files, ...(aliases ? { aliases } : {}) }).findings.map(
      (f) => f.ruleId,
    );
    const withoutAlias = scan({ files }).findings.map((f) => f.ruleId);
    expect(withAlias).toContain('env/secret-in-client');
    // Proves the fixture genuinely depends on alias resolution — not a trivially-flagged case.
    expect(withoutAlias).not.toContain('env/secret-in-client');
  });

  it('ci flags the alias-gated BLOCKER and exits non-zero', () => {
    const code = runCi({ cwd: root, annotations: false, severity: 'HIGH', strict: false });
    expect(code).toBe(EXIT.FINDINGS);
  });

  it('doctor flags the alias-gated BLOCKER and exits non-zero', async () => {
    const code = await runDoctor({ cwd: root });
    expect(code).toBe(EXIT.FINDINGS);
  });
});

describe('runDoctor exit codes', () => {
  let clean: string;
  beforeEach(() => {
    // An empty project has no findings and no live probe → must be EXIT.CLEAN.
    clean = mkdtempSync(join(tmpdir(), 'aegis-cli-clean-'));
  });
  afterEach(() => {
    rmSync(clean, { recursive: true, force: true });
  });

  it('returns EXIT.CLEAN on a finding-free project with no --url', async () => {
    expect(await runDoctor({ cwd: clean })).toBe(EXIT.CLEAN);
  });

  it('FAILS SECURE: a requested --url that cannot be reached returns EXIT.FINDINGS', async () => {
    // Port 1 reliably refuses; the live check could not run, so doctor must NOT report clean.
    const code = await runDoctor({ cwd: clean, url: 'http://127.0.0.1:1' });
    expect(code).toBe(EXIT.FINDINGS);
  });
});
