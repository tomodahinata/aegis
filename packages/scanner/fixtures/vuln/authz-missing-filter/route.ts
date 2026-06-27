import { supabase } from '@/lib/supabase';

// VULN (heuristic, medium confidence): the handler reads a user-scoped table with no auth lookup and
// no ownership filter. If `documents` is not protected by RLS, any caller reads every user's rows
// (IDOR). Aegis cannot verify RLS — this is a prompt to review.
export async function GET() {
  const { data } = await supabase.from('documents').select('*');
  return Response.json(data);
}
