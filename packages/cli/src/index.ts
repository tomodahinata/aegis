/**
 * `@aegiskit/cli` — the `aegis` command-line tool. The CLI binary is `./main.ts`; this entry
 * re-exports the testable, programmatically-usable building blocks.
 */

export { type CiArgs, runCi } from './commands/ci';
export {
  type DiffArgs,
  type DiffFormat,
  runDiff,
  sourcesAtRef,
  sourcesInWorktree,
} from './commands/diff';
export { type DoctorArgs, runDoctor } from './commands/doctor';
export { type InitArgs, runInit } from './commands/init';
export { type OutputFormat, runScan, type ScanArgs } from './commands/scan';
export { discoverFiles } from './discover';
export { EXIT, type ExitOptions, exitCodeFor } from './exit';
export { type ProjectScanOptions, scanProject } from './project-scan';
export { type RenderOptions, renderReport } from './reporters/pretty';
