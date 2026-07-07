/**
 * Scan-history ledger + remediation math for the compliance evidence report. SOC 2 CC7.1 auditors ask
 * not just "do you scan?" but "are findings remediated, and how fast?" — so a single scan is not evidence.
 * This records the OPEN finding fingerprints at each scan and derives, over the series, when each finding
 * was first seen and when it was resolved, plus aggregate mean-time-to-remediate — the remediation-over-
 * time story a raw findings dump cannot tell. Pure and deterministic (file I/O lives in the CLI); the wall
 * clock is injected as `now` so the math is fully testable.
 *
 * Honest scope (CLAUDE.md): this tracks the lifecycle of Aegis-detectable findings only. It is evidence
 * that detected gaps are being closed — never proof a control is effective, nor a substitute for an audit.
 */

import { fingerprintFinding } from '../baseline';
import type { ScanResult } from '../types';

/** One scan's snapshot: which finding fingerprints were OPEN, when, and at which commit (when known). */
export interface ScanRecord {
  /** ISO-8601 timestamp of the scan. */
  readonly scannedAt: string;
  /** The commit scanned, when CI provides it. */
  readonly commit?: string;
  /** Fingerprints of the findings open at this scan (sorted, deduped). */
  readonly openFingerprints: readonly string[];
}

export type ScanHistory = readonly ScanRecord[];

const MS_PER_DAY = 86_400_000;

/**
 * Build a scan record from a result. Reuses `fingerprintFinding` (the baseline's line-independent identity)
 * so a finding's history key matches its baseline key — one notion of "same finding" across the toolkit.
 */
export function toScanRecord(
  result: ScanResult,
  cwd: string,
  scannedAt: string,
  commit?: string,
): ScanRecord {
  const fingerprints = new Set<string>();
  for (const finding of result.findings) {
    fingerprints.add(fingerprintFinding(finding, cwd));
  }
  return {
    scannedAt,
    openFingerprints: [...fingerprints].sort(),
    ...(commit !== undefined ? { commit } : {}),
  };
}

/** Serialize one record as a single JSONL line (no trailing newline — the writer joins with `\n`). */
export function serializeScanRecord(record: ScanRecord): string {
  return JSON.stringify(record);
}

function isValidRecord(value: unknown): value is ScanRecord {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as { scannedAt?: unknown; openFingerprints?: unknown };
  return (
    typeof record.scannedAt === 'string' &&
    Array.isArray(record.openFingerprints) &&
    record.openFingerprints.every((fp) => typeof fp === 'string')
  );
}

/**
 * Parse the append-only JSONL ledger into chronologically-sorted records. A malformed or empty line is
 * skipped (fail-open: history is advisory evidence, so one corrupt append never sinks the whole report),
 * and records are sorted by `scannedAt` so out-of-order or concurrent appends still yield a correct series.
 */
export function parseHistory(jsonl: string): ScanHistory {
  const records: ScanRecord[] = [];
  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue; // skip a corrupt line rather than abort the report
    }
    if (isValidRecord(parsed)) {
      records.push(parsed);
    }
  }
  return records.sort((a, b) => a.scannedAt.localeCompare(b.scannedAt));
}

export type LifecycleStatus = 'open' | 'resolved';

/** The lifecycle of one finding across the scan series. */
export interface FindingLifecycle {
  readonly fingerprint: string;
  /** Earliest scan the finding appeared in. */
  readonly firstSeen: string;
  /** Latest scan the finding was still open in. */
  readonly lastSeen: string;
  /** The scan at which it was first observed gone (present in an earlier scan, absent here). */
  readonly resolvedAt?: string;
  readonly status: LifecycleStatus;
  /** Whole days: resolved ⇒ resolvedAt − firstSeen; open ⇒ now − firstSeen. Never negative. */
  readonly ageDays: number;
}

export interface RemediationSummary {
  readonly scans: number;
  readonly totalTracked: number;
  readonly open: number;
  readonly resolved: number;
  /** Mean whole-days from firstSeen to resolvedAt across resolved findings, or null if none resolved. */
  readonly meanTimeToRemediateDays: number | null;
  /** Age in whole days of the oldest currently-open finding, or null if none open. */
  readonly oldestOpenAgeDays: number | null;
  /** Per-finding lifecycles, oldest-first (most urgent open items surface at the top). */
  readonly lifecycles: readonly FindingLifecycle[];
}

function wholeDaysBetween(fromIso: string, toIso: string): number {
  const from = new Date(fromIso).getTime();
  const to = new Date(toIso).getTime();
  if (Number.isNaN(from) || Number.isNaN(to)) {
    return 0;
  }
  return Math.max(0, Math.floor((to - from) / MS_PER_DAY));
}

/**
 * Derive per-finding lifecycles and aggregate remediation stats from the scan series. "Resolved" means a
 * finding present in some earlier scan is absent from the MOST RECENT one; its `resolvedAt` is the first
 * scan (after it was last open) that no longer contained it — the auditable "detected fixed" timestamp.
 *
 * Simplification (documented): a finding that disappears and later reappears is treated by its current
 * state (open iff present in the latest scan) with `firstSeen` = its earliest appearance. Flapping findings
 * are therefore reported as a single lifecycle, not several — enough for remediation evidence, and never
 * over-claiming a fix that did not hold.
 */
export function computeRemediation(history: ScanHistory, now: string): RemediationSummary {
  const records = [...history].sort((a, b) => a.scannedAt.localeCompare(b.scannedAt));
  const latest = records[records.length - 1];
  const openNow = new Set(latest?.openFingerprints ?? []);

  // First/last scan each fingerprint was open in, in chronological order.
  const firstSeen = new Map<string, string>();
  const lastSeen = new Map<string, string>();
  for (const record of records) {
    for (const fp of record.openFingerprints) {
      if (!firstSeen.has(fp)) {
        firstSeen.set(fp, record.scannedAt);
      }
      lastSeen.set(fp, record.scannedAt);
    }
  }

  const lifecycles: FindingLifecycle[] = [];
  for (const [fp, first] of firstSeen) {
    const last = lastSeen.get(fp) ?? first;
    const isOpen = openNow.has(fp);
    if (isOpen) {
      lifecycles.push({
        fingerprint: fp,
        firstSeen: first,
        lastSeen: last,
        status: 'open',
        ageDays: wholeDaysBetween(first, now),
      });
      continue;
    }
    // Resolved: the first scan strictly after `last` is when it was observed gone.
    const resolvedAt = records.find((record) => record.scannedAt > last)?.scannedAt;
    lifecycles.push({
      fingerprint: fp,
      firstSeen: first,
      lastSeen: last,
      status: 'resolved',
      ageDays: resolvedAt !== undefined ? wholeDaysBetween(first, resolvedAt) : 0,
      ...(resolvedAt !== undefined ? { resolvedAt } : {}),
    });
  }

  lifecycles.sort((a, b) => b.ageDays - a.ageDays || a.fingerprint.localeCompare(b.fingerprint));

  const resolved = lifecycles.filter((l) => l.status === 'resolved');
  const open = lifecycles.filter((l) => l.status === 'open');
  const meanTimeToRemediateDays =
    resolved.length > 0
      ? Math.round(resolved.reduce((sum, l) => sum + l.ageDays, 0) / resolved.length)
      : null;
  const oldestOpenAgeDays = open.length > 0 ? Math.max(...open.map((l) => l.ageDays)) : null;

  return {
    scans: records.length,
    totalTracked: lifecycles.length,
    open: open.length,
    resolved: resolved.length,
    meanTimeToRemediateDays,
    oldestOpenAgeDays,
    lifecycles,
  };
}
