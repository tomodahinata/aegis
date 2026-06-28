-- SAFE: real-world RLS shapes that a 450-repo public-corpus field study showed the owner-scope rule used
-- to FALSE-POSITIVE on. The analyzer must produce ZERO findings here — this is the precision gate that
-- re-calibrates "precision 1.0" against the patterns production Supabase apps actually ship.

-- (1) Owner-scoped table that ALSO grants the backend service_role full access. service_role is the
--     privileged backend role (it bypasses RLS); a policy restricted to it is NOT "every authenticated
--     user reads every row" — regular callers are already scoped by the owner policy. ~47% of this rule's
--     real-world false positives were exactly this shape.
create table public.support_tickets (id uuid primary key, user_id uuid not null, body text);
alter table public.support_tickets enable row level security;
create policy "tickets_owner_read" on public.support_tickets for select to authenticated
  using (auth.uid() = user_id);
create policy "tickets_owner_write" on public.support_tickets for insert to authenticated
  with check (auth.uid() = user_id);
create policy "tickets_service_role" on public.support_tickets for all to service_role
  using (auth.role() = 'service_role') with check (auth.role() = 'service_role');

-- (2) Admin read access gated on a JWT app_metadata claim — authorizes by claim, not by session
--     existence. Restrictive to admins, not a broken-authz gap.
create table public.conversations (id uuid primary key, user_id uuid not null, body text);
alter table public.conversations enable row level security;
create policy "conversations_owner" on public.conversations for select to authenticated
  using (auth.uid() = user_id);
create policy "conversations_admin" on public.conversations for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'claims_admin')::boolean = true);

-- (3) Owner-bound via a cast on both operands (text id stored against a uuid claim).
create table public.profiles (id uuid primary key, user_id uuid not null, handle text);
alter table public.profiles enable row level security;
create policy "profiles_self" on public.profiles for select to authenticated
  using (auth.uid()::text = user_id::text);

-- (4) Owner-bound via the Supabase-recommended `(select auth.uid())` performance wrapper — including the
--     `as uid` alias the Supabase CLI generates, and multi-line formatting.
create table public.interview_sessions (id uuid primary key, user_id uuid not null, score int);
alter table public.interview_sessions enable row level security;
create policy "sessions_self_read" on public.interview_sessions for select to authenticated
  using (
    ( select auth.uid() as uid) = user_id
  );
create policy "sessions_self_write" on public.interview_sessions for insert to authenticated
  with check (( select auth.uid() as uid) = user_id);

-- (5) Owner-bound with stray whitespace in the auth call — `auth.uid ()`.
create table public.notes (id uuid primary key, user_id uuid not null, body text);
alter table public.notes enable row level security;
create policy "notes_self" on public.notes for select to authenticated
  using (auth.uid () = user_id);

-- (6) A service_role write policy with NO `TO` clause (so it applies to `public`, which includes `anon`).
--     An anonymous caller's role is `anon`, never `service_role`, so it can never satisfy this — it must
--     NOT be flagged `rls/anon-writable`. (Regression guard: classifying the role gate as `unknown` rather
--     than `role-delegated` made anon-writable fire here on real corpora.) Reads stay owner-scoped.
create table public.audit_log (id uuid primary key, user_id uuid not null, action text);
alter table public.audit_log enable row level security;
create policy "audit_owner_read" on public.audit_log for select to authenticated
  using (auth.uid() = user_id);
create policy "audit_backend_write" on public.audit_log for all
  using (auth.role() = 'service_role') with check (auth.role() = 'service_role');
