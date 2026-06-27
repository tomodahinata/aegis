import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { discoverRoutes, targetFromUrl } from './discover';

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aegis-dast-'));
  mkdirSync(join(root, 'app/api/users/[id]'), { recursive: true });
  writeFileSync(
    join(root, 'app/api/users/[id]/route.ts'),
    'export async function GET() {}\nexport async function POST() {}\n',
  );
  mkdirSync(join(root, 'app/api/health'), { recursive: true });
  writeFileSync(join(root, 'app/api/health/route.ts'), 'export function GET() {}\n');
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('discoverRoutes', () => {
  it('discovers route handlers with their methods and a concrete URL', () => {
    const targets = discoverRoutes(root, 'http://localhost:3000');
    const users = targets.find((t) => t.path === '/api/users/[id]');
    expect(users?.url).toBe('http://localhost:3000/api/users/1');
    expect([...(users?.methods ?? [])].sort()).toEqual(['GET', 'POST']);
    expect(targets.map((t) => t.path).sort()).toContain('/api/health');
  });
});

describe('targetFromUrl', () => {
  it('builds a single GET target for an explicit URL', () => {
    const target = targetFromUrl('http://localhost:3000/api/x?q=1', 'http://localhost:3000');
    expect(target.path).toBe('/api/x?q=1');
    expect([...target.methods]).toEqual(['GET']);
  });
});
