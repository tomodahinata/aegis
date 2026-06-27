import type { ScanResult } from '../types';

/** Machine-readable output: the `ScanResult` verbatim. */
export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
