import { exec } from 'node:child_process';

// VULN: request input is interpolated into a shell string. `?name=$(rm -rf /)` runs arbitrary
// commands on the server (command injection).
export async function POST(req: Request) {
  const { name } = await req.json();
  exec(`convert ${name} /tmp/out.png`, () => {});
  return new Response('ok');
}
