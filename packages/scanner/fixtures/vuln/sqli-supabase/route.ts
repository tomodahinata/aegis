import { supabase } from '@/lib/supabase';

// VULN: a value from the request body is concatenated into raw SQL run via rpc('exec_sql').
// An attacker sends tenant = "' OR '1'='1" to read or destroy other tenants' rows (SQL injection).
export async function POST(req: Request) {
  const { tenant } = await req.json();
  const query = `select * from documents where tenant = '${tenant}'`;
  const { data } = await supabase.rpc('exec_sql', { sql: query });
  return Response.json(data);
}
