// SAFE: input selects an operation from a fixed lookup table; nothing is evaluated as code, and the
// timer receives a function reference (not a string). A lookup by untrusted key returns trusted data.
export async function POST(req: Request) {
  const { op } = await req.json();
  const actions: Record<string, () => string> = { ping: () => 'pong' };
  const run = actions[op] ?? (() => 'noop');
  setTimeout(run, 10);
  return Response.json({ result: run() });
}
