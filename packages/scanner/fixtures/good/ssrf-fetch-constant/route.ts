// SAFE: a constant, trusted URL — no untrusted input reaches the fetch.
export async function GET() {
  const res = await fetch('https://api.example.com/health');
  return Response.json({ ok: res.ok });
}
