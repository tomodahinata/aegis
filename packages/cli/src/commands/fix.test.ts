import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '@aegiskit/scanner';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { discoverFiles } from '../discover';
import { EXIT } from '../exit';
import { type FixArgs, runFix } from './fix';

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
  const root = mkdtempSync(join(tmpdir(), 'aegis-fix-'));
  created.push(root);
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(root, name), content);
  }
  return root;
}

function run(args: FixArgs): { code: number; out: string } {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += String(chunk);
      return true;
    });
  try {
    const code = runFix(args);
    return { code, out };
  } finally {
    spy.mockRestore();
  }
}

const baseArgs = (cwd: string): FixArgs => ({
  cwd,
  write: false,
  format: 'pretty',
  noColor: true,
  plain: false,
});

function hasCsrf(root: string): boolean {
  return scan({ files: discoverFiles(root) }).findings.some(
    (f) => f.ruleId === 'csrf/missing-origin-check',
  );
}

describe('runFix — preview', () => {
  it('does not modify files and reports the auto-fix', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const { code, out } = run(baseArgs(root));
    expect(code).toBe(EXIT.CLEAN);
    expect(readFileSync(join(root, 'route.ts'), 'utf8')).toBe(VULN_ROUTE); // untouched
    expect(out).toContain('AUTO ✎');
    expect(out).toContain('Wrap POST with secureRoute');
  });
});

describe('runFix --write', () => {
  it('applies the wrap and resolves the finding (idempotent on re-run)', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    expect(hasCsrf(root)).toBe(true);

    run({ ...baseArgs(root), write: true });
    const after = readFileSync(join(root, 'route.ts'), 'utf8');
    expect(after).toContain('export const POST = secureRoute({ origin: true }');
    expect(hasCsrf(root)).toBe(false);

    // Idempotent: nothing left to do, file unchanged.
    const { out } = run({ ...baseArgs(root), write: true });
    expect(out).toContain('Nothing to remediate');
    expect(readFileSync(join(root, 'route.ts'), 'utf8')).toBe(after);
  });

  it('scaffolds a secure() middleware for the missing-headers finding', () => {
    const root = tmpProject({ 'next.config.ts': 'export default {};\n' });
    run({ ...baseArgs(root), write: true });
    const middleware = join(root, 'middleware.ts');
    expect(existsSync(middleware)).toBe(true);
    expect(readFileSync(middleware, 'utf8')).toContain('secure()');
    // The scaffold resolves the headers finding on a re-scan.
    expect(
      scan({ files: discoverFiles(root) }).findings.some(
        (f) => f.ruleId === 'headers/missing-security-headers',
      ),
    ).toBe(false);
  });
});

describe('runFix --format json (agent handoff)', () => {
  it('emits the structured plan with auto/guided counts', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const { out } = run({ ...baseArgs(root), format: 'json' });
    const parsed = JSON.parse(out);
    expect(parsed.summary.auto).toBe(1);
    expect(parsed.items[0].mode).toBe('auto');
    expect(parsed.items[0].ruleId).toBe('csrf/missing-origin-check');
  });
});

describe('runFix --rule', () => {
  it('limits the plan to the named rule', () => {
    const root = tmpProject({ 'route.ts': VULN_ROUTE });
    const matched = JSON.parse(
      run({ ...baseArgs(root), format: 'json', rule: 'csrf/missing-origin-check' }).out,
    );
    expect(matched.summary.total).toBe(1);

    const none = JSON.parse(run({ ...baseArgs(root), format: 'json', rule: 'no/such-rule' }).out);
    expect(none.summary.total).toBe(0);
  });
});
