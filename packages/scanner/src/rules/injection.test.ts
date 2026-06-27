import { describe, expect, it } from 'vitest';
import { scan } from '../engine';
import type { Finding } from '../types';

function findingFor(path: string, source: string, ruleId: string): Finding | undefined {
  return scan({ files: [path], readFile: () => source }).findings.find((f) => f.ruleId === ruleId);
}

const ROUTE = '/app/api/x/route.ts';

describe('injection/sql', () => {
  it('flags untrusted input concatenated into an rpc SQL query, with a dataflow trace', () => {
    const finding = findingFor(
      ROUTE,
      `import { supabase } from '@/lib/supabase';
       export async function POST(req: Request) {
         const { tenant } = await req.json();
         const { data } = await supabase.rpc('exec_sql', { sql: \`select * from t where x = '\${tenant}'\` });
         return Response.json(data);
       }`,
      'injection/sql',
    );
    expect(finding?.severity).toBe('BLOCKER');
    expect(finding?.confidence).toBe('high');
    expect(finding?.trace?.[0]?.kind).toBe('source');
    expect(finding?.trace?.at(-1)?.kind).toBe('sink');
  });

  it('does NOT flag a value passed as a bound rpc parameter', () => {
    expect(
      findingFor(
        ROUTE,
        `import { supabase } from '@/lib/supabase';
         export async function POST(req: Request) {
           const { tenant } = await req.json();
           return Response.json(await supabase.rpc('fn', { tenant_id: tenant }));
         }`,
        'injection/sql',
      ),
    ).toBeUndefined();
  });
});

describe('ssrf/tainted-fetch', () => {
  it('flags a server-side fetch of a tainted absolute URL', () => {
    expect(
      findingFor(
        ROUTE,
        `import { NextRequest } from 'next/server';
         export async function GET(req: NextRequest) {
           const u = req.nextUrl.searchParams.get('u') ?? '';
           return fetch(u);
         }`,
        'ssrf/tainted-fetch',
      ),
    ).toBeDefined();
  });

  it('does NOT run in a client component (context-gated)', () => {
    expect(
      findingFor(
        '/app/widget.tsx',
        `'use client';
         import { useSearchParams } from 'next/navigation';
         export function W() { const u = useSearchParams().get('u') ?? ''; void fetch(u); return null; }`,
        'ssrf/tainted-fetch',
      ),
    ).toBeUndefined();
  });
});

describe('redirect/open-redirect', () => {
  it('caps confidence to medium so it informs without blocking CI', () => {
    const finding = findingFor(
      ROUTE,
      `import { redirect } from 'next/navigation';
       import { NextRequest } from 'next/server';
       export async function GET(req: NextRequest) {
         const next = req.nextUrl.searchParams.get('next') ?? '';
         redirect(next);
       }`,
      'redirect/open-redirect',
    );
    expect(finding?.confidence).toBe('medium');
    expect(finding?.severity).toBe('MEDIUM');
  });

  it('does NOT flag a relative redirect target', () => {
    expect(
      findingFor(
        ROUTE,
        `import { redirect } from 'next/navigation';
         import { NextRequest } from 'next/server';
         export async function GET(req: NextRequest) {
           const id = req.nextUrl.searchParams.get('id') ?? '';
           redirect(\`/dashboard/\${id}\`);
         }`,
        'redirect/open-redirect',
      ),
    ).toBeUndefined();
  });
});
