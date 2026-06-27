# @aegiskit/store-supabase

A persistent Aegis `EventStore` backed by Supabase/Postgres, shipping a migration with **Row Level Security enabled by default**.

## Install + migrate

```bash
pnpm add @aegiskit/store-supabase @supabase/supabase-js
# apply the migration (RLS on; service_role writes, admins read):
psql "$DATABASE_URL" -f node_modules/@aegiskit/store-supabase/migrations/0001_aegis_events.sql
```

## Use

```ts
import { createClient } from '@supabase/supabase-js';
import { createSupabaseEventStore } from '@aegiskit/store-supabase';

// Use the SERVICE_ROLE key on the ingestion side (it bypasses RLS to write).
const supabase = createClient(url, serviceRoleKey);
const store = createSupabaseEventStore({ client: supabase });

await store.append(events); // insert … on conflict (id) do nothing — idempotent
const recent = await store.query({ type: 'origin_block', limit: 50 });
const summary = await store.summary({ since, until });
```

- **Idempotency** is the table's primary key.
- **RLS** is the access-control boundary Aegis preaches: the migration enables it with an admin-only read policy and no write policy (writes happen via the `service_role` key, which bypasses RLS). A `tenant_id` seam is documented for multi-tenant deployments.

## License

MIT
