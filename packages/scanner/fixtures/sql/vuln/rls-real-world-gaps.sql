-- VULN: genuine authenticated-only gaps written the way real production schemas write them — the quoted
-- (pg_dump / declarative) form, the `(select …)` performance wrapper, and an OR-disjunction that re-widens
-- access back to every authenticated user. Each table carries an ownership column, so
-- `rls/policy-not-owner-scoped` MUST fire (at medium confidence). Recall lock for the real-world shapes the
-- precision hardening must NOT have suppressed.

-- Quoted-identifier form of `auth.role() = 'authenticated'` (declarative schema). Every logged-in caller
-- has role 'authenticated', so this reads EVERY row, not just the owner's.
create table public.quoted_docs (id uuid primary key, user_id uuid not null, body text);
alter table public.quoted_docs enable row level security;
create policy "quoted_docs_read" on public.quoted_docs for select to authenticated
  using (("auth"."role"() = 'authenticated'::"text"));

-- The `(select auth.uid())` performance wrapper with IS NOT NULL — a session-existence proof, not an
-- ownership binding.
create table public.wrapped_docs (id uuid primary key, owner_id uuid not null, body text);
alter table public.wrapped_docs enable row level security;
create policy "wrapped_docs_read" on public.wrapped_docs for select to authenticated
  using ((select auth.uid()) is not null);

-- An OR-disjunction whose `auth.uid() IS NOT NULL` arm re-widens access to every authenticated user, even
-- though the other arm is a (restrictive) service_role gate. The gap is still real.
create table public.mixed_docs (id uuid primary key, user_id uuid not null, body text);
alter table public.mixed_docs enable row level security;
create policy "mixed_docs_read" on public.mixed_docs for select to authenticated
  using (auth.role() = 'service_role' or auth.uid() is not null);
