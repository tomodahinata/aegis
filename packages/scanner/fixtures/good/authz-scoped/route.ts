import { supabase } from '@/lib/supabase';

// SAFE: the handler authenticates the caller and scopes the query to their own rows. The auth lookup
// and ownership filter satisfy the heuristic, so no finding.
export async function GET() {
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return new Response('unauthorized', { status: 401 });
  }
  const { data } = await supabase.from('documents').select('*').eq('user_id', user.id);
  return Response.json(data);
}
