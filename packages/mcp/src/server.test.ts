import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, describe, expect, it } from 'vitest';
import { createAegisMcpServer } from './server';

const RLS_GAP_SQL = `create table public.notes (id uuid primary key, user_id uuid not null, body text);
alter table public.notes enable row level security;
create policy "read" on public.notes for select to authenticated using (auth.role() = 'authenticated');
`;

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tmpProject(): string {
  const root = mkdtempSync(join(tmpdir(), 'aegis-mcp-srv-'));
  created.push(root);
  const path = join(root, 'supabase/migrations/0001.sql');
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, RLS_GAP_SQL);
  return root;
}

/** Connect an in-memory MCP client to a fresh Aegis server (no real transport needed). */
async function connect(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createAegisMcpServer();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientTransport);
  return client;
}

function firstText(result: unknown): string {
  const content = (result as { content?: { type: string; text?: string }[] }).content ?? [];
  return content.map((c) => c.text ?? '').join('\n');
}

describe('Aegis MCP server', () => {
  it('advertises scan_project, explain_finding, and explain_policy_diff', async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'explain_finding',
      'explain_policy_diff',
      'scan_project',
    ]);
  });

  it('scan_project returns a prioritized summary an agent can act on', async () => {
    const client = await connect();
    const res = await client.callTool({ name: 'scan_project', arguments: { path: tmpProject() } });
    const text = firstText(res);
    expect(text).toContain('Aegis scanned');
    expect(text).toContain('rls/policy-not-owner-scoped');
    expect(text).toContain('fingerprint:');
  });

  it('explain_finding hands back the why + a suggested policy for a scanned fingerprint', async () => {
    const client = await connect();
    const root = tmpProject();
    const summary = firstText(
      await client.callTool({ name: 'scan_project', arguments: { path: root } }),
    );
    const fingerprint = /fingerprint: ([a-f0-9]{64})/.exec(summary)?.[1];
    expect(fingerprint).toBeTruthy();
    const detail = firstText(
      await client.callTool({
        name: 'explain_finding',
        arguments: { path: root, fingerprint },
      }),
    );
    expect(detail).toContain('Why:');
    expect(detail).toContain('auth.uid() = user_id');
  });

  it('explain_finding reports an error for an unknown fingerprint', async () => {
    const client = await connect();
    const res = await client.callTool({
      name: 'explain_finding',
      arguments: { path: tmpProject(), fingerprint: 'nope' },
    });
    expect((res as { isError?: boolean }).isError).toBe(true);
    expect(firstText(res)).toContain('No finding');
  });
});
