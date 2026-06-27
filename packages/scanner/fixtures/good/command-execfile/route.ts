import { execFile } from 'node:child_process';

// SAFE: execFile runs a fixed binary with the input as a separate ARGUMENT (not a shell string), so
// there is no shell to inject into. The command position is a constant.
export async function POST(req: Request) {
  const { name } = await req.json();
  execFile('convert', [name, '/tmp/out.png'], () => {});
  return new Response('ok');
}
