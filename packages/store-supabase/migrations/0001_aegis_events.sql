-- Aegis security events table for @aegiskit/store-supabase.
-- Row Level Security is ENABLED BY DEFAULT: the ingestion service writes via the service_role
-- key (which bypasses RLS), and only authenticated admins may read. No anon/public access.

create table if not exists public.aegis_events (
  id          text primary key,                       -- sink-minted idempotency key
  type        text        not null,
  received_at timestamptz not null default now(),      -- server receive time
  at          bigint      not null,                    -- client/edge emit time (epoch ms)
  ip          text,
  path        text,
  method      text,
  request_id  text,
  data        jsonb       not null default '{}'::jsonb  -- type-specific fields
);

create index if not exists aegis_events_received_at_idx
  on public.aegis_events (received_at desc);
create index if not exists aegis_events_type_received_at_idx
  on public.aegis_events (type, received_at desc);

alter table public.aegis_events enable row level security;

-- Read: authenticated users whose JWT carries role = 'admin'. (No insert/update/delete policy
-- exists, so with RLS enabled all writes are denied EXCEPT via the service_role key, which
-- bypasses RLS — exactly how the ingestion endpoint should write.)
drop policy if exists "aegis_events_admin_read" on public.aegis_events;
create policy "aegis_events_admin_read"
  on public.aegis_events
  for select
  to authenticated
  using ((auth.jwt() ->> 'role') = 'admin');

-- Multi-tenant seam (deferred): add a `tenant_id text not null` column, include it in the
-- primary key / indexes, and add `and tenant_id = (auth.jwt() ->> 'tenant_id')` to the policy.
