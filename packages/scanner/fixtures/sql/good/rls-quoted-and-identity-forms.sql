-- SAFE: the PostgreSQL quoted-identifier forms that `pg_dump` and Supabase declarative `supabase/schemas`
-- emit, plus the identity-function role gates real apps use. A 450-repo public-corpus field study showed
-- the owner-scope and anon-writable rules used to FALSE-POSITIVE on every one of these. The analyzer must
-- produce ZERO findings here — this locks "precision 1.0" against the declarative-schema shape (a whole
-- class of real repos), not just the bare-identifier shape.

-- (1) Declarative-schema (quoted) owner binding + a quoted service_role backend policy with no TO clause
--     (so it reaches `public`/`anon`). An anon's role is never `service_role`; the gate is not satisfiable
--     by anon and not the "every authenticated user" gap. Neither owner-scope nor anon-writable may fire.
create table public.documents (id uuid primary key, user_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "documents_owner" on public.documents for all to authenticated
  using (("auth"."uid"() = "user_id")) with check (("auth"."uid"() = "user_id"));
create policy "documents_backend" on public.documents for all
  using (("auth"."role"() = 'service_role'::"text"))
  with check (("auth"."role"() = 'service_role'::"text"));

-- (2) Quoted JWT admin-claim gate (declarative form). Authorizes by claim; an anon has no such claim.
create table public.conversations (id uuid primary key, user_id uuid not null, body text);
alter table public.conversations enable row level security;
create policy "conversations_owner" on public.conversations for select to authenticated
  using (("auth"."uid"() = "user_id"));
create policy "conversations_admin" on public.conversations for select to authenticated
  using (((("auth"."jwt"() -> 'app_metadata'::"text") ->> 'role'::"text") = 'admin'::"text"));

-- (3) Role gates via the Postgres identity functions `current_setting` / `current_user`, not `auth.*`.
--     An anon's role is `anon`, never `service_role`, so these restrict — they are not anon-satisfiable.
create table public.org_settings (id uuid primary key, org_id uuid not null, value text);
alter table public.org_settings enable row level security;
create policy "settings_tenant" on public.org_settings for select to authenticated
  using (("org_id" = ("current_setting"('app.current_org', true))::"uuid"));
create policy "settings_backend" on public.org_settings for all
  using ((current_setting('role', true) = 'service_role'))
  with check ((current_setting('role', true) = 'service_role'));

-- (4) `auth.uid() IN (cols)` — a participant / multi-owner binding (chat sender/receiver, shared docs).
--     The caller must BE one of these columns; an anon (null uid) is in no such list. Owner-bound.
create table public.messages (id uuid primary key, sender_id uuid not null, receiver_id uuid not null, body text);
alter table public.messages enable row level security;
create policy "messages_participant" on public.messages for all to authenticated
  using (("auth"."uid"() in ("sender_id", "receiver_id")))
  with check (("auth"."uid"() in ("sender_id", "receiver_id")));

-- (5) Authorization delegated to a quoted custom function `public.is_team_member(...)`. Aegis cannot
--     analyze the function body, so it conservatively does NOT flag (fail-secure) — and an anon cannot
--     satisfy a membership check, so anon-writable must stay silent too.
create table public.team_docs (id uuid primary key, team_id uuid not null, body text);
alter table public.team_docs enable row level security;
create policy "team_docs_member" on public.team_docs for all to authenticated
  using (("public"."is_team_member"("team_id", "auth"."uid"())))
  with check (("public"."is_team_member"("team_id", "auth"."uid"())));
