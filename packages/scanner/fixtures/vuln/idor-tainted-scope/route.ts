import { supabase } from '@/lib/supabase';

// VULN (high confidence — a proven request→ownership-filter dataflow, not a heuristic): the handler
// scopes `documents` by `user_id`, but takes that id straight from the request body. Any caller reads
// another user's rows by changing `userId` — textbook IDOR / broken object-level authorization. The
// ownership filter must use the authenticated session's id, never request input.
export async function POST(req: Request) {
  const { userId } = await req.json();
  const { data } = await supabase.from('documents').select('*').eq('user_id', userId);
  return Response.json(data);
}
