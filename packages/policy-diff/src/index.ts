/**
 * `@aegiskit/policy-diff` — the semantic access diff behind the Aegis Policy Gate: compare the
 * Supabase RLS surface (policies, RLS state, table grants) of two migration states and report, in
 * plain language, who can newly read or write what. Fail-safe by contract: anything unverifiable is
 * `requires-review`, never silence. Build the two models with `buildRlsModel` from
 * `@aegiskit/scanner` (base ref sources vs head ref sources) and hand them to `diffAccess`.
 */

export type {
  AccessDelta,
  AccessTransition,
  Breadth,
  DeltaChange,
  DeltaKind,
  DeltaSeverity,
  DeltaSummary,
  DiffOptions,
  PolicySummary,
} from './diff';
export { diffAccess, summarizeDeltas } from './diff';
export { COMMENT_MARKER, type RenderOptions, renderDeltaMarkdown } from './render';
