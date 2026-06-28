-- SAFE: regression corpus for the SQL-analysis fixes. The analyzer must produce ZERO findings here.

-- NEGATIVE for SEC-01: a FOR ALL policy whose WITH CHECK *also* scopes writes to the owner. The read
-- side (USING) and the write side (WITH CHECK) are both owner-bound, so this is the correct pattern and
-- must NOT be flagged — the write-check gap only exists when WITH CHECK weakens to "is authenticated".
create table public.attachments_ok (id uuid primary key, user_id uuid not null, url text);
alter table public.attachments_ok enable row level security;
create policy "attachments_ok_all" on public.attachments_ok for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- NEGATIVE for COR-01: an `auth.*` token that appears only inside a SQL comment or a string literal is
-- NOT real code. Classifying on the raw text would wrongly read these as authenticated-only and fire a
-- false positive; the comment/string-masked classification keeps them at `unknown` (not flagged).
create table public.articles (id uuid primary key, user_id uuid not null, status text, note text);
alter table public.articles enable row level security;
create policy "articles_published" on public.articles for select to authenticated
  using (status = 'published' /* not auth.uid() — published rows are public on purpose */);
create policy "articles_note" on public.articles for select to authenticated
  using (note = 'see auth.role() docs');

-- NEGATIVE for the deny-all idiom: an append-only audit log makes itself immutable with `USING (false)`
-- (no caller can ever satisfy it) and grants only SELECT. This is the SAFEST possible write design, yet
-- the row-state regex once mistook `false` for an anon-satisfiable predicate and fired anon-writable HIGH.
-- The `'deny'` predicate class keeps it silent.
create table public.audit_log (id uuid primary key, actor uuid, action text, at timestamptz default now());
alter table public.audit_log enable row level security;
create policy "audit_log_select" on public.audit_log for select to authenticated using (true);
create policy "audit_log_no_update" on public.audit_log for update using (false) with check (false);
create policy "audit_log_no_delete" on public.audit_log for delete using (false);
grant select on public.audit_log to authenticated;
