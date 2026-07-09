#!/usr/bin/env node
/**
 * Week-0 go/no-go measurements for the Policy Gate (PR-time semantic RLS diff).
 *
 * Replays each repo's migration SEQUENCE (timestamped filenames = change history — no git history
 * needed) through the shipped `buildRlsModel`, then asks the four questions that gate the build:
 *
 *   (a) TRIGGER FREQUENCY  — how often do real repos merge an access-relevant migration?
 *   (b) REQUIRES_REVIEW    — under fail-safe diff semantics (unknown/function-delegated ⇒ review),
 *                            what share of access-relevant migrations would flag for review (noise)?
 *   (c) FUNCTION-DELEGATED — prevalence of custom-helper predicates (drives the allowlist design).
 *   (d) STORAGE POLICIES   — share of repos with policies on storage.objects (sizes the Phase-1
 *                            schema-blindness hole), plus DISABLE RLS / REVOKE statement counts
 *                            (sizes the other fail-open holes on real data).
 *
 * The per-migration delta classifier here is a MEASUREMENT PROXY, deliberately simpler than the
 * product diff engine (no permissive/restrictive matrix): it exists to size rates, not to gate PRs.
 *
 * Usage: node measure.mjs [N=300]   (reads ../rls-precision-study/data/repos.txt; writes data/)
 * Requires: `pnpm --filter @aegiskit/scanner build` first (imports the built dist).
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

const REPOS_TXT = path.join(HERE, '../rls-precision-study/data/repos.txt');
const DATA = path.join(HERE, 'data');
const CLONES = path.join(DATA, 'clones');
const OUT = path.join(DATA, 'rows.jsonl');
const N = Number(process.argv[2] ?? 300);
const SEED = 20260708;
const CONCURRENCY = 4;
const MAX_MIGRATIONS_REPLAY = 400; // O(n²) replay guard; repos beyond this are prevalence-only

// ── seeded sample (mulberry32; reproducible without Math.random) ──────────────────────────────────
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

// ── access-relevance + hole-sizing regexes (statement-agnostic; measurement only) ─────────────────
const ACCESS_RELEVANT =
  /\b(?:create|alter|drop)\s+policy\b|\brow\s+level\s+security\b|^\s*(?:grant|revoke)\s/im;
const DISABLE_RLS = /\balter\s+table\s+[^;]*?\bdisable\s+row\s+level\s+security\b/gi;
const REVOKE = /^\s*revoke\s/gim;
const STORAGE_POLICY =
  /\b(?:create|alter|drop)\s+policy\s+(?:"[^"]+"|[\w-]+)\s+on\s+"?storage"?\s*\.\s*"?objects"?/gi;

// Effective class (mirrors packages/scanner/src/internal/sql/predicate.ts effectivePolicyClass —
// inlined because it is not exported; INSERT is governed by WITH CHECK, everything else by USING).
function effectiveClass(p) {
  if (p.command === 'insert') return p.checkClass;
  return p.usingClass !== 'absent' ? p.usingClass : p.checkClass;
}

// Permissiveness rank for the measurement proxy. `unknown`/`function-delegated` never rank — they
// route to REQUIRES_REVIEW (the fail-safe class the product diff will use).
const RANK = {
  deny: 0,
  'owner-bound': 1,
  'role-delegated': 2,
  'authenticated-only': 3,
  unconditional: 4,
};
const REVIEW_CLASSES = new Set(['unknown', 'function-delegated', 'absent']);

/**
 * Key a policy for cross-model matching. The public PolicyInfo does NOT expose the policy NAME (the
 * model's internal identity key) — a gap the product diff engine must fix by exporting it. For this
 * measurement, (table, command, restrictive, roles) + a duplicate counter is a serviceable proxy: a
 * predicate change on a unique key reads as a class transition; a rename reads as drop+add.
 */
function policyMap(model) {
  const map = new Map();
  const seen = new Map();
  for (const p of model.policies) {
    const base = `${p.table}\x00${p.command}\x00${p.restrictive}\x00${[...p.roles].sort().join(',')}`;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    map.set(n === 0 ? base : `${base}\x00#${n}`, p);
  }
  return map;
}

/** Classify one migration step by comparing successive models. Returns flags, not a single verdict. */
function classifyStep(prev, cur) {
  const flags = { widening: false, narrowing: false, review: false };
  const prevPolicies = policyMap(prev);
  const curPolicies = policyMap(cur);

  for (const [key, cp] of curPolicies) {
    const pp = prevPolicies.get(key);
    const cc = effectiveClass(cp);
    if (!pp) {
      // Policy added: a PERMISSIVE policy grants access that did not exist (widening, unless deny);
      // a RESTRICTIVE one narrows. Unverifiable classes route to review.
      if (REVIEW_CLASSES.has(cc)) flags.review = true;
      else if (cp.restrictive) flags.narrowing = true;
      else if (cc !== 'deny') flags.widening = true;
      continue;
    }
    const pc = effectiveClass(pp);
    if (pc === cc && pp.restrictive === cp.restrictive) continue;
    if (REVIEW_CLASSES.has(pc) || REVIEW_CLASSES.has(cc)) {
      flags.review = true;
    } else if ((RANK[cc] ?? 99) > (RANK[pc] ?? 99)) {
      flags.widening = true;
    } else if ((RANK[cc] ?? 99) < (RANK[pc] ?? 99)) {
      flags.narrowing = true;
    }
  }
  for (const [key, pp] of prevPolicies) {
    if (curPolicies.has(key)) continue;
    const pc = effectiveClass(pp);
    if (REVIEW_CLASSES.has(pc)) flags.review = true;
    else if (pp.restrictive)
      flags.widening = true; // dropping a deny-refinement widens
    else flags.narrowing = true; // dropping a grant narrows
  }
  // RLS enablement transitions (disable is invisible to the current model — sized separately).
  for (const [name, ct] of cur.tables) {
    const pt = prev.tables.get(name);
    if (pt && pt.rlsEnabled && !ct.rlsEnabled) flags.widening = true;
    if (pt && !pt.rlsEnabled && ct.rlsEnabled) flags.narrowing = true;
  }
  if (cur.grants.length > prev.grants.length) flags.widening = true;
  return flags;
}

/** Parse the Supabase timestamp prefix (YYYYMMDD[HHMMSS]) from a migration filename. */
function parseTs(base) {
  const m = /^(\d{8,14})/.exec(base);
  if (!m) return undefined;
  const s = m[1].padEnd(14, '0');
  const [y, mo, d, h, mi] = [
    s.slice(0, 4),
    s.slice(4, 6),
    s.slice(6, 8),
    s.slice(8, 10),
    s.slice(10, 12),
  ];
  const t = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:00Z`);
  return Number.isNaN(t) ? undefined : t;
}

async function run(cmd, args, opts = {}) {
  try {
    await execFileP(cmd, args, { timeout: opts.timeout ?? 90_000 });
    return true;
  } catch {
    return false;
  }
}

async function measureRepo(repo) {
  const key = repo.replace('/', '__');
  const dir = path.join(CLONES, key);
  await fs.rm(dir, { recursive: true, force: true });
  const cloned = await run('git', [
    'clone',
    '--depth',
    '1',
    '--filter=blob:none',
    '--no-checkout',
    `https://github.com/${repo}.git`,
    dir,
  ]);
  if (!cloned) return { repo, status: 'clone_fail' };
  await run(
    'git',
    [
      '-C',
      dir,
      'sparse-checkout',
      'set',
      '--no-cone',
      '**/supabase/migrations/**',
      '**/supabase/schemas/**',
    ],
    { timeout: 30_000 },
  );
  await run('git', ['-C', dir, 'checkout'], { timeout: 60_000 });

  const sqlPaths = [];
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
      else if (
        e.isFile() &&
        e.name.endsWith('.sql') &&
        /\/supabase\/(migrations|schemas)\//.test(p.replace(/\\/g, '/'))
      )
        sqlPaths.push(p);
    }
  }
  await walk(dir);
  if (sqlPaths.length === 0) {
    await fs.rm(dir, { recursive: true, force: true });
    return { repo, status: 'no_sql' };
  }

  const sources = [];
  for (const p of sqlPaths.sort()) {
    sources.push({ path: p, text: await fs.readFile(p, 'utf8').catch(() => '') });
  }
  const allText = sources.map((s) => s.text).join('\n');

  // Prevalence metrics (whole-repo, order-independent).
  const finalModel = buildRlsModel(sources);
  const classes = {};
  for (const p of finalModel.policies) {
    const c = effectiveClass(p);
    classes[c] = (classes[c] ?? 0) + 1;
  }
  const prevalence = {
    policies: finalModel.policies.length,
    classes,
    storagePolicyStmts: (allText.match(STORAGE_POLICY) ?? []).length,
    disableRlsStmts: (allText.match(DISABLE_RLS) ?? []).length,
    revokeStmts: (allText.match(REVOKE) ?? []).length,
  };

  // Sequence replay over supabase/migrations only (timestamped, incremental by convention).
  const migrations = sources
    .filter((s) => /\/supabase\/migrations\//.test(s.path.replace(/\\/g, '/')))
    .map((s) => ({ ...s, base: path.basename(s.path), ts: parseTs(path.basename(s.path)) }))
    .sort((a, b) => (a.base < b.base ? -1 : 1));

  const steps = [];
  if (migrations.length >= 1 && migrations.length <= MAX_MIGRATIONS_REPLAY) {
    let prevModel = buildRlsModel([]);
    for (let k = 0; k < migrations.length; k += 1) {
      const m = migrations[k];
      const accessRelevant = ACCESS_RELEVANT.test(m.text);
      let flags = { widening: false, narrowing: false, review: false };
      if (accessRelevant) {
        const curModel = buildRlsModel(migrations.slice(0, k + 1));
        flags = classifyStep(prevModel, curModel);
        prevModel = curModel;
      }
      steps.push({ ts: m.ts, accessRelevant, ...flags });
    }
  }

  await fs.rm(dir, { recursive: true, force: true });
  return { repo, status: 'ok', migrationCount: migrations.length, prevalence, steps };
}

// ── main ──────────────────────────────────────────────────────────────────────────────────────────
await fs.mkdir(CLONES, { recursive: true });
const pool = (await fs.readFile(REPOS_TXT, 'utf8'))
  .split('\n')
  .map((s) => s.trim())
  .filter(Boolean);
const repos = seededSample(pool, N, SEED);
console.log(`measuring ${repos.length} repos (seed ${SEED}) …`);
await fs.writeFile(OUT, '');

let done = 0;
const queue = [...repos];
async function worker() {
  for (;;) {
    const repo = queue.shift();
    if (!repo) return;
    const row = await measureRepo(repo).catch((e) => ({ repo, status: `err:${e?.message ?? e}` }));
    await fs.appendFile(OUT, `${JSON.stringify(row)}\n`);
    done += 1;
    if (done % 20 === 0) console.log(`[${done}/${repos.length}]`);
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));
console.log(`done → ${OUT}`);
