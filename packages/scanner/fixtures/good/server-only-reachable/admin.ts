import 'server-only';
import { createClient } from '@supabase/supabase-js';

// A Client Component imports this (see panel.tsx), so the import graph reaches it. But
// `import 'server-only'` guarantees Next never bundles it into the browser — it is a
// reachability barrier. Neither the service_role client nor the secret read must be flagged
// (supabase/service-role-outside-admin, env/secret-in-client). This is the canonical safe
// counterpart to vuln/secret-reachable-from-client, which lacks the guard.
export function createAdminClient() {
  return createClient(process.env.SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');
}
