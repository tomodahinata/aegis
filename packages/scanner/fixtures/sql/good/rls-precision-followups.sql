-- Regression lock (good corpus → MUST stay silent): false-positive classes closed after the 12.7k-repo
-- field study. Unique `pf_` names avoid collision with the co-scanned good fixtures. NOTE: the procedural
-- DO-loop enable class is deliberately covered by ISOLATED unit tests (model.test.ts / scan-sql.test.ts),
-- not here — its repo-wide `proceduralRlsEnable` flag would suppress table-without-rls across the whole
-- combined good corpus and mask an unrelated regression.

-- 1) The Supabase `(select … AS <alias>)` performance wrapper is owner-scoping / role-gating, never the
--    owner-scope gap, and must not trip anon-writable. (Bare/plain-wrapped forms live in the other fixtures.)
create table public.pf_owner (id uuid primary key, user_id uuid not null);
alter table public.pf_owner enable row level security;
create policy pf_owner_sel on public.pf_owner for select
  using ((select auth.uid() as uid) = user_id);
create policy pf_owner_svc on public.pf_owner for all to service_role
  using (((select auth.role() as role) = 'service_role'));

-- 2) A policy scoped ONLY to service_role/admin is trusted backend access — service_role bypasses RLS
--    (BYPASSRLS), so an unconditional `true` there is idiomatic, not a permissive-write gap.
create table public.pf_backend (id uuid primary key, user_id uuid not null);
alter table public.pf_backend enable row level security;
create policy pf_backend_all on public.pf_backend for all to service_role
  using (true) with check (true);
create policy pf_backend_owner on public.pf_backend for select
  using (auth.uid() = user_id);
