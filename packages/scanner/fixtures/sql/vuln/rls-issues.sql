-- VULN: each statement trips a distinct RLS rule.

-- rls/table-without-rls: a public table with RLS never enabled (anon/authenticated can read+write all rows).
create table public.orders (id uuid primary key, total int, customer_email text);

-- rls/security-definer-search-path: runs as owner, search_path not pinned (privilege escalation).
create function public.purge() returns void language sql security definer
  as $$ delete from public.orders; $$;

create table public.notes (id uuid primary key, owner uuid);
alter table public.notes enable row level security;

-- rls/write-policy-without-check: INSERT policy with no WITH CHECK (no USING to fall back on → unrestricted insert).
create policy "notes_insert" on public.notes for insert to authenticated;

-- rls/permissive-write-policy: a write command with an unconditional true predicate.
create policy "notes_all" on public.notes for all to authenticated using (true) with check (true);

-- rls/anon-table-grant: a NON-RLS table (orders, above) granted to anon.
grant select on public.orders to anon;
