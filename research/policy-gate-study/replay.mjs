#!/usr/bin/env node
/**
 * Corpus replay with the REAL diff engine (@aegiskit/policy-diff), replacing the measurement proxy
 * of measure.mjs: for every repo in a seeded sample, replay the migration sequence and diff every
 * consecutive state pair with `diffAccess`. Launch-gate purpose: (1) the engine must never crash on
 * real-world SQL; (2) verdict distribution should be sane (WIDENING present, review bounded);
 * (3) emit a WIDENING sample for the manual precision audit.
 *
 * Usage: node replay.mjs [N=60]
 * Requires: pnpm --filter @aegiskit/scanner build && pnpm --filter @aegiskit/policy-diff build
 */
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const { buildRlsModel } = await import(path.join(ROOT, 'packages/scanner/dist/index.js'));
const { diffAccess } = await import(path.join(ROOT, 'packages/policy-diff/dist/index.js'));

const REPOS_TXT = path.join(HERE, '../rls-precision-study/data/repos.txt');
const DATA = path.join(HERE, 'data');
const CLONES = path.join(DATA, 'clones');
const OUT = path.join(DATA, 'replay.jsonl');
const SAMPLE_OUT = path.join(DATA, 'widening-sample.md');
const N = Number(process.argv[2] ?? 60);
const SEED = 20260709; // different seed from measure.mjs: an independent draw
const CONCURRENCY = 4;
const MAX_MIGRATIONS = 300;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function seededSample(pool, n, seed) {
  const rand = mulberry32(seed);
  const a = [...pool];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, Math.min(n, a.length));
}

async function run(cmd, args, timeout = 90_000) {
  try {
    await execFileP(cmd, args, { timeout });
    return true;
  } catch {
    return false;
  }
}

async function replayRepo(repo) {
  const key = repo.replace('/', '__');
  const dir = path.join(CLONES, key);
  await fs.rm(dir, { recursive: true, force: true });
  if (
    !(await run('git', [
      'clone',
      '--depth',
      '1',
      '--filter=blob:none',
      '--no-checkout',
      `https://github.com/${repo}.git`,
      dir,
    ]))
  ) {
    return { repo, status: 'clone_fail' };
  }
  await run(
    'git',
    ['-C', dir, 'sparse-checkout', 'set', '--no-cone', '**/supabase/migrations/**'],
    30_000,
  );
  await run('git', ['-C', dir, 'checkout'], 60_000);

  const files = [];
  async function walk(d) {
    let entries;
    try {
      entries = await fs.readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory() && e.name !== '.git') await walk(p);
      else if (e.isFile() && e.name.endsWith('.sql') && /\/supabase\/migrations\//.test(p))
        files.push(p);
    }
  }
  await walk(dir);
  const migrations = [];
  for (const p of files.sort()) {
    migrations.push({
      path: p.slice(dir.length),
      text: await fs.readFile(p, 'utf8').catch(() => ''),
    });
  }
  await fs.rm(dir, { recursive: true, force: true });
  if (migrations.length === 0) return { repo, status: 'no_sql' };
  if (migrations.length > MAX_MIGRATIONS) return { repo, status: 'too_many' };

  const counts = { widening: 0, narrowing: 0, 'requires-review': 0, neutral: 0 };
  let high = 0;
  let steps = 0;
  const wideningSamples = [];
  let prev = buildRlsModel([]);
  for (let k = 0; k < migrations.length; k += 1) {
    const cur = buildRlsModel(migrations.slice(0, k + 1));
    let deltas;
    try {
      deltas = diffAccess(prev, cur);
    } catch (e) {
      return { repo, status: `engine_crash:${e?.message ?? e}`, at: migrations[k].path };
    }
    for (const d of deltas) {
      counts[d.kind] = (counts[d.kind] ?? 0) + 1;
      if (d.severity === 'high' && (d.kind === 'widening' || d.kind === 'requires-review'))
        high += 1;
      if (d.kind === 'widening' && d.severity === 'high' && wideningSamples.length < 3) {
        wideningSamples.push({ step: migrations[k].path, summary: d.summary });
      }
    }
    if (deltas.length > 0) steps += 1;
    prev = cur;
  }
  return {
    repo,
    status: 'ok',
    migrations: migrations.length,
    stepsWithDeltas: steps,
    counts,
    high,
    wideningSamples,
  };
}

await fs.mkdir(CLONES, { recursive: true });
const pool = (await fs.readFile(REPOS_TXT, 'utf8'))
  .split('\n')
  .map((s) => s.trim())
  .filter(Boolean);
const repos = seededSample(pool, N, SEED);
console.log(`replaying ${repos.length} repos with the real engine (seed ${SEED}) …`);
await fs.writeFile(OUT, '');

let done = 0;
const queue = [...repos];
async function worker() {
  for (;;) {
    const repo = queue.shift();
    if (!repo) return;
    const row = await replayRepo(repo).catch((e) => ({ repo, status: `err:${e?.message ?? e}` }));
    await fs.appendFile(OUT, `${JSON.stringify(row)}\n`);
    done += 1;
    if (done % 10 === 0) console.log(`[${done}/${repos.length}]`);
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));

// Aggregate + emit the manual-audit sample (anonymized: step paths only, no repo names in the md).
const rows = (await fs.readFile(OUT, 'utf8'))
  .split('\n')
  .filter(Boolean)
  .map((l) => JSON.parse(l));
const ok = rows.filter((r) => r.status === 'ok');
const crashes = rows.filter((r) => String(r.status).startsWith('engine_crash'));
const total = { widening: 0, narrowing: 0, 'requires-review': 0, neutral: 0, high: 0 };
for (const r of ok) {
  for (const k of Object.keys(r.counts)) total[k] += r.counts[k];
  total.high += r.high;
}
const sample = ok.flatMap((r) =>
  r.wideningSamples.map((s) => `- [ ] \`${s.step}\` — ${s.summary}`),
);
await fs.writeFile(
  SAMPLE_OUT,
  `# WIDENING(high) manual-audit sample (${sample.length} items)\n\n${sample.join('\n')}\n`,
);
console.log(
  `repos ok=${ok.length} crash=${crashes.length} other=${rows.length - ok.length - crashes.length}`,
);
console.log('verdicts:', JSON.stringify(total));
if (crashes.length > 0) console.log('CRASHES:', JSON.stringify(crashes, null, 1));
console.log(`widening sample → ${SAMPLE_OUT}`);
