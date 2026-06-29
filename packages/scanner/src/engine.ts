import { readFileSync } from 'node:fs';
import { classifyFile } from './classify';
import { analysisErrorFinding, ruleErrorFinding } from './internal/analysis-error';
import { collectImports, importsServerOnly, parseSource, rangeOf } from './internal/ast';
import { buildScopeIndex, findTaintFlows, type ScopeIndex } from './internal/dataflow';
import {
  type FileSuppressions,
  isSuppressed,
  parseSuppressions,
  SUPPRESSION_WITHOUT_REASON_RULE,
} from './internal/suppressions';
import type { TaintFlow, TaintSpec } from './internal/taint-descriptors';
import { computeReachableFromClient, type GraphNode, resolveImportPath } from './module-graph';
import { docsUrlFor, type FileInfo, type Rule, type RuleContext } from './rule';
import { ALL_RULES } from './rules';
import { emptySummary, type Finding, type PassCheck, type ScanResult } from './types';

export interface ScanOptions {
  readonly files: readonly string[];
  /** Rules to run. Default: all built-in rules. */
  readonly rules?: readonly Rule[];
  /** File reader (for tests/virtual FS). Default: `fs.readFileSync`. */
  readonly readFile?: (path: string) => string;
  /** Import alias map, e.g. `{ '@/': '/abs/project/src/' }`. */
  readonly aliases?: Record<string, string>;
  /** Include suppressed findings (flagged `suppressed: true`) instead of dropping them. */
  readonly showSuppressed?: boolean;
  /** Resolve each finding's safe auto-fix (for `aegis fix`). Off by default — adds zero hot-path cost. */
  readonly computeFixes?: boolean;
}

interface MutableFileInfo {
  path: string;
  text: string;
  sourceFile: FileInfo['sourceFile'];
  classification: FileInfo['classification'];
  imports: FileInfo['imports'];
  reachableFromClient: boolean;
  suppressions: FileSuppressions;
}

/**
 * A module the browser bundle can never include — a hard server/client boundary proven by Next.js's
 * build contract (not a filename guess), so it and any subtree reachable only through it are excluded
 * from client reachability. Two kinds:
 *   - `import 'server-only'` — Next throws at build if such a module is bundled for the browser; and
 *   - a `"use server"` Server Actions module — a Client Component importing it compiles to an RPC
 *     stub, so the module body and its entire import subtree stay on the server (every export is an
 *     async server function). Omitting this barrier flagged secrets behind the idiomatic Client
 *     Component → Server Action → server-lib chain (e.g. `getStripe()` reading `STRIPE_SECRET_KEY`)
 *     as client-reachable — a false positive, since that code never reaches the browser bundle.
 */
function isClientBundleBarrier(info: MutableFileInfo): boolean {
  return (
    info.classification.isServerAction ||
    (info.text.includes('server-only') && importsServerOnly(info.sourceFile))
  );
}

export function scan(options: ScanOptions): ScanResult {
  const started = Date.now();
  const read = options.readFile ?? ((path: string) => readFileSync(path, 'utf8'));
  const rules = options.rules ?? ALL_RULES;

  // Per-scan taint caches (local → fresh each call, never leak across scans). The scope index is
  // source-shaped (spec-independent), so it is built once per file and reused by every taint rule;
  // flows are then memoized per (file, spec) keyed on the rule's frozen spec identity.
  const scopeIndexByFile = new Map<string, ScopeIndex>();
  const flowCacheByFile = new Map<string, WeakMap<TaintSpec, readonly TaintFlow[]>>();

  // 1. Parse + classify every file. Isolate each file: a single unreadable/unparseable one must
  // never abort the whole scan (fail secure) — it is skipped and surfaced as a LOW finding.
  const infos = new Map<string, MutableFileInfo>();
  const analysisErrors: Finding[] = [];
  for (const path of options.files) {
    let text: string;
    let sourceFile: FileInfo['sourceFile'];
    try {
      text = read(path);
      sourceFile = parseSource(path, text);
    } catch (error) {
      analysisErrors.push(analysisErrorFinding(path, error));
      continue;
    }
    infos.set(path, {
      path,
      text,
      sourceFile,
      classification: classifyFile(path, sourceFile),
      imports: collectImports(sourceFile),
      reachableFromClient: false,
      suppressions: parseSuppressions(text),
    });
  }

  // 2. Resolve internal import edges, then mark everything reachable from a Client Component.
  // A module that the browser bundle can never include is a barrier: excluded from reachability
  // along with any subtree reachable only through it (see `isClientBundleBarrier`).
  const known = new Set(infos.keys());
  const graph = new Map<string, GraphNode>();
  const barriers = new Set<string>();
  for (const info of infos.values()) {
    const resolved = new Set<string>();
    for (const binding of info.imports) {
      const target = resolveImportPath(info.path, binding.module, known, options.aliases);
      if (target) {
        resolved.add(target);
      }
    }
    graph.set(info.path, { path: info.path, importsResolved: resolved });
    if (isClientBundleBarrier(info)) {
      barriers.add(info.path);
    }
  }
  const clientSeeds = [...infos.values()]
    .filter((info) => info.classification.context === 'client')
    .map((info) => info.path);
  for (const path of computeReachableFromClient(graph, clientSeeds, barriers)) {
    const info = infos.get(path);
    if (info) {
      info.reachableFromClient = true;
    }
  }

  // 3. Run each applicable rule per file, applying inline suppressions.
  const files: ReadonlyMap<string, FileInfo> = infos;
  const showSuppressed = options.showSuppressed ?? false;
  const computeFixes = options.computeFixes ?? false;
  const findings: Finding[] = [...analysisErrors];
  const passes: PassCheck[] = [];
  let suppressedCount = 0;

  for (const info of infos.values()) {
    const importIndex = new Map(
      info.imports.map((binding) => [binding.localName, binding] as const),
    );
    for (const rule of rules) {
      if (!rule.appliesTo(info)) {
        continue;
      }
      const ctx: RuleContext = {
        file: info,
        files,
        resolveBinding: (name) => importIndex.get(name),
        resolveModule: (specifier) => {
          const target = resolveImportPath(info.path, specifier, known, options.aliases);
          return target ? files.get(target) : undefined;
        },
        taint: (spec) => {
          let perFile = flowCacheByFile.get(info.path);
          if (!perFile) {
            perFile = new WeakMap();
            flowCacheByFile.set(info.path, perFile);
          }
          const cached = perFile.get(spec);
          if (cached) {
            return cached;
          }
          let index = scopeIndexByFile.get(info.path);
          if (!index) {
            index = buildScopeIndex(info.sourceFile);
            scopeIndexByFile.set(info.path, index);
          }
          const flows = findTaintFlows(info, spec, index);
          perFile.set(spec, flows);
          return flows;
        },
        report: (input) => {
          const range = rangeOf(info.sourceFile, input.node);
          const suppressed = isSuppressed(info.suppressions, rule.meta.id, range.startLine);
          if (suppressed) {
            suppressedCount += 1;
            if (!showSuppressed) {
              return;
            }
          }
          // Resolve the safe auto-fix lazily, and only when asked — most scans never fix.
          const fix = computeFixes ? input.fix?.() : undefined;
          findings.push({
            ruleId: rule.meta.id,
            severity: input.severity ?? rule.meta.severity,
            confidence: input.confidence,
            message: input.message,
            file: info.path,
            range,
            docsUrl: rule.meta.docsUrl,
            remediation: input.remediation,
            ...(rule.meta.owasp !== undefined ? { owasp: rule.meta.owasp } : {}),
            ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
            ...(input.trace !== undefined ? { trace: input.trace } : {}),
            ...(suppressed ? { suppressed: true } : {}),
            ...(fix !== undefined ? { fix } : {}),
          });
        },
        pass: (detail) => {
          passes.push({ ruleId: rule.meta.id, title: rule.meta.title, detail, file: info.path });
        },
      };
      // Isolate each rule: a throw on a pathological AST must surface as a finding, never abort the
      // whole scan and silently drop every other rule's and file's findings (fail open). Mirrors the
      // per-file parse isolation above.
      try {
        rule.check(ctx);
      } catch (error) {
        findings.push(ruleErrorFinding(info.path, rule.meta.id, error));
      }
    }
  }

  // A suppression without a reason is itself a (low) finding — never silent. These are not
  // themselves suppressible, closing the loophole where a reasonless disable hides its own warning.
  for (const info of infos.values()) {
    for (const suppression of info.suppressions.all) {
      if (suppression.reason === undefined) {
        findings.push({
          ruleId: SUPPRESSION_WITHOUT_REASON_RULE,
          severity: 'LOW',
          confidence: 'high',
          message: `Suppression of "${suppression.ruleId}" gives no reason — add "-- <reason>" so the next reader knows why it is safe.`,
          file: info.path,
          range: {
            startLine: suppression.directiveLine,
            startColumn: 1,
            endLine: suppression.directiveLine,
            endColumn: 1,
          },
          docsUrl: docsUrlFor(SUPPRESSION_WITHOUT_REASON_RULE),
          remediation: 'Append "-- <reason>" to the aegis-disable directive explaining why.',
        });
      }
    }
  }

  // Deterministic ordering for stable snapshots and SARIF fingerprints.
  findings.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return {
    findings,
    passes,
    summary,
    scannedFiles: infos.size,
    suppressedCount,
    durationMs: Date.now() - started,
  };
}
