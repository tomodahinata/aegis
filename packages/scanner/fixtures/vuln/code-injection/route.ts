// VULN: a request value is evaluated as JavaScript. `{ "expr": "process.exit(1)" }` runs arbitrary
// code with the server's privileges (code injection).
export async function POST(req: Request) {
  const { expr } = await req.json();
  const result = eval(expr);
  return Response.json({ result });
}
