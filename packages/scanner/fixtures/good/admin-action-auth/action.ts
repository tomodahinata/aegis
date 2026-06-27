'use server';

import { getAdminUser } from '@/lib/auth';
import { supabase } from '@/lib/supabase';

// SAFE: an admin Server Action that authenticates via getAdminUser() before querying (the real SpoLove
// pattern). The authz heuristic must recognize getAdminUser() as a gate — a substring `getuser(` does
// not appear in `getAdminUser`, so this is the case that used to false-fire.
export async function listGames() {
  const user = await getAdminUser();
  if (!user) {
    return { error: 'forbidden' as const };
  }
  const { data } = await supabase.from('games').select('*');
  return { data };
}
