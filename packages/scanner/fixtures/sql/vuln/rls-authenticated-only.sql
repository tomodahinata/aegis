-- VULN: RLS is enabled and each table has a policy — but the policy only checks that the caller is
-- authenticated, never scoping rows to the owner. Every logged-in user can reach every row. Each table
-- carries an ownership column, so `rls/policy-not-owner-scoped` must fire (at medium confidence).

-- rls/policy-not-owner-scoped: SELECT gated by auth.role() only (any authenticated user reads all rows).
create table public.documents (id uuid primary key, user_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "documents_read" on public.documents for select to authenticated
  using (auth.role() = 'authenticated');

-- rls/policy-not-owner-scoped: SELECT gated by auth.uid() IS NOT NULL only.
create table public.invoices (id uuid primary key, tenant_id uuid not null, amount int);
alter table public.invoices enable row level security;
create policy "invoices_read" on public.invoices for select to authenticated
  using (auth.uid() is not null);

-- rls/policy-not-owner-scoped: a WRITE path (FOR ALL) gated only by "is logged in".
create table public.tickets (id uuid primary key, owner_id uuid not null, title text);
alter table public.tickets enable row level security;
create policy "tickets_all" on public.tickets for all to authenticated
  using (auth.uid() is not null) with check (auth.uid() is not null);

-- rls/policy-not-owner-scoped (SEC-01 WRITE-CHECK gap): the USING clause correctly scopes READS to the
-- owner, but the WITH CHECK only verifies the caller is authenticated — so a logged-in user can INSERT
-- rows they don't own or rewrite user_id to someone else's (CWE-639 IDOR write). A USING-only check
-- misses this; the WITH CHECK governs writes independently.
create table public.attachments (id uuid primary key, user_id uuid not null, url text);
alter table public.attachments enable row level security;
create policy "attachments_all" on public.attachments for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() is not null);
