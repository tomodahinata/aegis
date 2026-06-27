import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// VULN: a request-controlled filename is joined into a path with no normalization. `?file=../../.env`
// escapes the intended directory and reads arbitrary files (path traversal).
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get('file') ?? '';
  const contents = await readFile(join('/var/data', name), 'utf8');
  return new Response(contents);
}
