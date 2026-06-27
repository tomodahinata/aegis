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
