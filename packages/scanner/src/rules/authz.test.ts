import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

function scanFiles(files: Record<string, string>) {
  return scan({ files: Object.keys(files), readFile: (p) => files[p] ?? '' });
}

function authzFindings(files: Record<string, string>): number {
  return scanFiles(files).findings.filter((f) => f.ruleId === 'authz/missing-access-filter').length;
}

function idorFindings(files: Record<string, string>) {
  return scanFiles(files).findings.filter((f) => f.ruleId === 'authz/idor-tainted-scope');
}

describe('authz/missing-access-filter — interprocedural auth resolution', () => {
  it('passes when the query is gated by an imported helper that authenticates (regardless of its name)', () => {
    // `ensureCaller` does NOT match the name heuristic — only following the import reveals the auth.
    const files = {
      '/app/api/x/route.ts':
        "import { ensureCaller } from './auth'; export async function GET() { await ensureCaller(); return supabase.from('orders').select('*'); }",
      '/app/api/x/auth.ts':
        'export const ensureCaller = async () => { const { data } = await authClient.auth.getUser(); return data; };',
    };
    expect(authzFindings(files)).toBe(0);
  });

  it('still flags a query with no authorization signal anywhere (no import, no gate)', () => {
    const files = {
      '/app/api/y/route.ts':
        "export async function GET() { return supabase.from('orders').select('*'); }",
    };
    expect(authzFindings(files)).toBeGreaterThan(0);
  });

  it('does not treat an imported NON-auth helper as a gate (fail-secure)', () => {
    const files = {
      '/app/api/z/route.ts':
        "import { formatRow } from './util'; export async function GET() { const r = await supabase.from('orders').select('*'); return formatRow(r); }",
      '/app/api/z/util.ts': 'export const formatRow = (r: unknown) => JSON.stringify(r);',
    };
    expect(authzFindings(files)).toBeGreaterThan(0);
  });

  it('does not flag a route handler whose only `.from()` is a stdlib factory (Array/Buffer.from)', () => {
    // `.from()` matched the cheap pre-filter, but neither call is a data query — must not be an IDOR FP.
    const files = {
      '/app/api/list/route.ts':
        "export async function GET() { const xs = Array.from([1, 2, 3]); const b = Buffer.from('cafe', 'hex'); return Response.json({ n: xs.length, b: b.length }); }",
    };
    expect(authzFindings(files)).toBe(0);
  });
});

describe('authz/idor-tainted-scope — ownership filter bound to request input', () => {
  it('flags .eq("user_id", <request body>) as a high-confidence IDOR carrying a source→sink trace', () => {
    const files = {
      '/app/api/docs/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { userId } = await req.json();\n  const { data } = await supabase.from('documents').select('*').eq('user_id', userId);\n  return Response.json(data);\n}",
    };
    const found = idorFindings(files);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('high'); // a proven flow → can fail CI
    expect(found[0]?.severity).toBe('HIGH');
    expect(found[0]?.trace?.[0]?.kind).toBe('source');
    expect(found[0]?.trace?.at(-1)?.kind).toBe('sink');
  });

  it('flags an ownership filter fed by a route param (request-controlled → high confidence)', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function GET(_req: Request, { params }: { params: { id: string } }) {\n  const { data } = await supabase.from('docs').select('*').eq('owner_id', params.id);\n  return Response.json(data);\n}",
    };
    const found = idorFindings(files);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('high');
  });

  it('flags an ownership filter fed by a URL query parameter (request-controlled → high confidence)', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const { data } = await supabase.from('docs').select('*').eq('tenant_id', searchParams.get('t'));\n  return Response.json(data);\n}",
    };
    const found = idorFindings(files);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('high');
  });

  it('flags the .match({ user_id }) object form', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { uid } = await req.json();\n  const { data } = await supabase.from('docs').select('*').match({ user_id: uid });\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(1);
  });

  it('flags the three-argument `.filter("user_id", "eq", <request value>)` form', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { uid } = await req.json();\n  const { data } = await supabase.from('docs').select('*').filter('user_id', 'eq', uid);\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(1);
  });

  it.each([
    'neq',
    'in',
  ])('flags the .%s ownership filter — the whole PostgREST comparison family, not just .eq', (op) => {
    const files = {
      '/app/api/d/route.ts': `import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { uid } = await req.json();\n  const { data } = await supabase.from('docs').select('*').${op}('tenant_id', uid);\n  return Response.json(data);\n}`,
    };
    expect(idorFindings(files)).toHaveLength(1);
  });

  it('reports a multi-column .match({ user_id, tenant_id }) as ONE finding per query site (dedup)', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { uid, tid } = await req.json();\n  const { data } = await supabase.from('docs').select('*').match({ user_id: uid, tenant_id: tid });\n  return Response.json(data);\n}",
    };
    // Two tainted ownership columns → two flows, but one query site → one finding.
    expect(idorFindings(files)).toHaveLength(1);
  });

  it('is NOT rescued by a numeric cast — authorization is not a sanitization problem', () => {
    // `Number(attackerId)` is still an attacker-CHOSEN id; the row it selects is another user's.
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  const { data } = await supabase.from('docs').select('*').eq('user_id', Number(searchParams.get('uid')));\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(1);
  });

  it('does NOT flag an ownership filter scoped by the SESSION user (the safe pattern)', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function GET() {\n  const { data: { user } } = await supabase.auth.getUser();\n  const { data } = await supabase.from('docs').select('*').eq('user_id', user.id);\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(0);
  });

  it('does NOT flag a fetch-by-primary-key `.eq("id", params.id)` (the ubiquitous safe pattern)', () => {
    const files = {
      '/app/api/d/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function GET(_req: Request, { params }: { params: { id: string } }) {\n  const { data } = await supabase.from('docs').select('*').eq('id', params.id);\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(0);
  });

  it('does NOT flag the service-role/admin client — it bypasses RLS by design (fail-secure)', () => {
    const files = {
      '/app/api/admin/route.ts':
        "import { createAdminClient } from '@/lib/admin';\nexport async function POST(req: Request) {\n  const { userId } = await req.json();\n  const db = createAdminClient();\n  const { data } = await db.from('docs').select('*').eq('user_id', userId);\n  return Response.json(data);\n}",
    };
    expect(idorFindings(files)).toHaveLength(0);
  });

  it('defers the heuristic rule: a tainted ownership filter yields the IDOR finding and no contradictory pass', () => {
    const files = {
      '/app/api/docs/route.ts':
        "import { supabase } from '@/lib/supabase';\nexport async function POST(req: Request) {\n  const { userId } = await req.json();\n  const { data } = await supabase.from('documents').select('*').eq('user_id', userId);\n  return Response.json(data);\n}",
    };
    const result = scanFiles(files);
    expect(result.findings.filter((f) => f.ruleId === 'authz/idor-tainted-scope')).toHaveLength(1);
    // The medium "no visible check" heuristic must NOT also fire (it would be a weaker duplicate)…
    expect(result.findings.filter((f) => f.ruleId === 'authz/missing-access-filter')).toHaveLength(
      0,
    );
    // …and must NOT emit a green "scoped by an ownership filter" pass that contradicts the IDOR.
    expect(result.passes.filter((p) => p.ruleId === 'authz/missing-access-filter')).toHaveLength(0);
  });
});
