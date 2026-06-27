'use client';

import { createClient } from '@supabase/supabase-js';

// service_role bypasses RLS and is constructed in a Client Component → full data breach.
export const supabase = createClient(
  'https://example.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? '',
);
