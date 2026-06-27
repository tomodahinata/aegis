import { z } from 'zod';
import { supabase } from '@/lib/supabase';

// SAFE: the value is validated to a NUMBER before use. A number cannot carry SQL metacharacters, so
// the sanitizer neutralizes the SQL sink and there is no finding (even interpolated into the query).
export async function POST(req: Request) {
  const body = await req.json();
  const id = z.coerce.number().parse(body.id);
  const { data } = await supabase.rpc('exec_sql', { sql: `select * from documents where id = ${id}` });
  return Response.json(data);
}
