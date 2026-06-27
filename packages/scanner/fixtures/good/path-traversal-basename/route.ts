import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

// SAFE: the filename is reduced to a single segment with basename() before being joined, so `../`
// traversal is stripped and the fs-path sink is neutralized.
export async function GET(req: Request) {
  const requested = new URL(req.url).searchParams.get('file') ?? '';
  const safe = basename(requested);
  const contents = await readFile(join('/var/data', safe), 'utf8');
  return new Response(contents);
}
