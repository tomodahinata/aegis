import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EXIT } from '../exit';
import { runScan, type ScanArgs } from './scan';

// A route that reads the session cookie and mutates without CSRF protection — the scanner flags it,
// which gives the baseline tests below real findings to capture and then mute.
const VULN_ROUTE = `import { cookies } from 'next/headers';

export async function POST(req: Request) {
  const store = await cookies();
  const session = store.get('session');
  const body = await req.json();
  void session;
  void body;
  return Response.json({ ok: true });
}
`;

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tmpProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'aegis-scan-'));
  created.push(root);
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(root, name), content);
  }
  return root;
}

function baseArgs(cwd: string): ScanArgs {
  return {
    cwd,
    format: 'pretty',
    severity: 'HIGH',
    strict: false,
    noColor: true,
    plain: false,
    showSuppressed: false,
    updateBaseline: false,
  };
}

function run(args: ScanArgs): { code: number; out: string } {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += String(chunk);
      return true;
    });
  try {
    const code = runScan(args);
    return { code, out };
  } finally {
    spy.mockRestore();
  }
}

describe('runScan output formats', () => {
  it('prints a human report and exits clean on a project with no findings', () => {
    const root = tmpProject({
      'page.tsx': 'export default function Page() {\n  return null;\n}\n',
    });
    const { code, out } = run(baseArgs(root));
    expect(code).toBe(EXIT.CLEAN);
    // Assert the actual clean-report marker, not merely that *something* was printed — an error banner
    // would also be non-empty, so `length > 0` could mask a regression.
    expect(out).toMatch(/No security findings/);
  });

  it('emits machine-readable JSON when --format json', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const { out } = run({ ...baseArgs(root), format: 'json' });
    expect(JSON.parse(out)).toHaveProperty('findings');
  });

  it('emits a SARIF log when --format sarif', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const { out } = run({ ...baseArgs(root), format: 'sarif' });
    const sarif = JSON.parse(out);
    expect(String(sarif.$schema)).toMatch(/sarif/i);
    expect(sarif.runs).toBeDefined();
  });
});

describe('runScan baselines', () => {
  it('writes a baseline of the current findings and exits clean (--update-baseline)', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const { code, out } = run({ ...baseArgs(root), updateBaseline: true });
    expect(code).toBe(EXIT.CLEAN);
    expect(existsSync(join(root, 'aegis-baseline.json'))).toBe(true);
    expect(out).toMatch(/baseline entries/);
  });

  it('mutes findings already captured by the auto-detected baseline', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    // Snapshot every current finding into the default baseline, then re-scan: all should be muted.
    run({ ...baseArgs(root), updateBaseline: true });
    const { code, out } = run(baseArgs(root));
    expect(code).toBe(EXIT.CLEAN);
    expect(out).toMatch(/muted by baseline/);
  });

  it('honors an explicit --baseline path', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const baseline = join(root, 'custom-baseline.json');
    run({ ...baseArgs(root), baseline, updateBaseline: true });
    expect(existsSync(baseline)).toBe(true);
    expect(run({ ...baseArgs(root), baseline }).code).toBe(EXIT.CLEAN);
  });
});
