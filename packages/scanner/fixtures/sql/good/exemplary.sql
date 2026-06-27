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
