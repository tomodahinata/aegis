import { supabase } from '@/lib/supabase';

// SAFE: the request value is passed to an RPC as a BOUND parameter, never concatenated into SQL.
// The injection/sql rule must not flag a parameterized rpc({ … }) call.
export async function POST(req: Request) {
  const { id } = await req.json();
  const { data } = await supabase.rpc('get_widget', { widget_id: id });
  return Response.json(data);
}
