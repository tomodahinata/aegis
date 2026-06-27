import { supabase } from '@/lib/supabase';

// SAFE: the request value is passed as a BOUND parameter, never concatenated into SQL text. The
// dataflow ends at a non-SQL position, so no finding.
export async function POST(req: Request) {
  const { tenant } = await req.json();
  const { data } = await supabase.rpc('documents_for_tenant', { tenant_id: tenant });
  return Response.json(data);
}
