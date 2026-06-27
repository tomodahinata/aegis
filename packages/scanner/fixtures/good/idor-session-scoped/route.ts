import { supabase } from '@/lib/supabase';

// SAFE: the ownership filter uses the SESSION user's id; the request value (`page`) drives pagination
// only — it never reaches the ownership column. Proves authz/idor-tainted-scope keys on the FILTER
// VALUE's origin (session vs request), not the mere presence of request input in the handler.
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const page = Number(searchParams.get('page') ?? '0');
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return new Response('unauthorized', { status: 401 });
  }
  const { data } = await supabase
    .from('documents')
    .select('*')
    .eq('user_id', user.id)
    .range(page * 20, page * 20 + 19);
  return Response.json(data);
}
