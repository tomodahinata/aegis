import 'server-only';
import { createClient } from '@supabase/supabase-js';

// service_role client constructed in a server-only module, behind a factory — correct usage.
export function createAdminClient() {
  return createClient(process.env.SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');
}
