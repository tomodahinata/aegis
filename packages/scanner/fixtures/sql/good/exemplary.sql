-- SAFE: a production-grade RLS design (mirrors SpoLove). The analyzer must produce ZERO findings here.

create table public.profiles (id uuid primary key, user_id uuid not null, email text);
alter table public.profiles enable row level security;
create policy "profiles_self" on public.profiles for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Public reference data: read-only USING (true) is intentional and safe (not flagged).
create table public.regions (code text primary key, name text not null);
alter table public.regions enable row level security;
create policy "regions_read" on public.regions for select to authenticated using (true);

-- SECURITY DEFINER helper with a PINNED search_path (no privilege-escalation vector).
create function public.is_team_member(t uuid) returns boolean
  language sql stable security definer set search_path = public
  as $$ select exists (select 1 from public.team_members m where m.team_id = t and m.user_id = auth.uid()); $$;

grant select on public.regions to authenticated;

-- Org-shared table with an ownership-looking column, correctly scoped by a membership subquery
-- (role-delegated). The caller only sees rows for teams they belong to — NOT flagged.
create table public.team_docs (id uuid primary key, team_id uuid not null, body text);
alter table public.team_docs enable row level security;
create policy "team_docs_read" on public.team_docs for select to authenticated
  using (team_id in (select team_id from public.team_members where user_id = auth.uid()));

-- Ownership scoping delegated to a custom predicate function (verified elsewhere). Aegis cannot
-- analyze the function body, so it conservatively does NOT flag this (fail secure).
create table public.records (id uuid primary key, user_id uuid not null, data text);
alter table public.records enable row level security;
create policy "records_access" on public.records for all to authenticated
  using (public.has_access(id)) with check (public.has_access(id));

-- Owner-bound via the JWT subject claim — the correct pattern in its non-auth.uid() form. NOT flagged.
create table public.sessions_log (id uuid primary key, user_id uuid not null, ip text);
alter table public.sessions_log enable row level security;
create policy "sessions_self" on public.sessions_log for select to authenticated
  using (auth.jwt() ->> 'sub' = user_id::text);
