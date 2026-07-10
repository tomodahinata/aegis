-- Regression lock (good corpus → MUST stay silent): `ALTER TABLE IF EXISTS …` is a common defensive
-- migration idiom and must be honored by EVERY ALTER TABLE handler, identically to the bare form. Before
-- the shared `ALTER_TABLE_HEAD` fix, only CREATE/DROP TABLE honored the existence clause, so `IF EXISTS`
-- on ENABLE produced a CI-breaking false `table-without-rls`, on DISABLE was missed (fail OPEN), and on
-- ADD COLUMN dropped the ownership column (silencing the owner-scope rule). Every table below is correctly
-- RLS-enabled and owner-scoped; unique `ifx_` names avoid collision with the co-scanned good fixtures.

-- ENABLE via `ALTER TABLE IF EXISTS` (previously misread as "no RLS").
create table if not exists public.ifx_notes (id uuid primary key, user_id uuid not null);
alter table if exists public.ifx_notes enable row level security;
create policy ifx_notes_owner on public.ifx_notes for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Ownership column added via `ALTER TABLE IF EXISTS … ADD COLUMN` (previously dropped → rule silenced).
create table if not exists public.ifx_events (id uuid primary key);
alter table if exists public.ifx_events add column user_id uuid not null;
alter table if exists public.ifx_events enable row level security;
create policy ifx_events_owner on public.ifx_events for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- `IF EXISTS` and `ONLY` together, in PostgreSQL's declared order.
create table if not exists public.ifx_tasks (id uuid primary key, user_id uuid not null);
alter table if exists only public.ifx_tasks enable row level security;
create policy ifx_tasks_owner on public.ifx_tasks for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);
