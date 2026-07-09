/**
 * The testable logic behind the `explain_policy_diff` MCP tool: compute the semantic RLS access
 * delta between a git base ref and the working tree, and render it for an agent to cite.
 *
 * Positioning note (why this tool exists): LLM code reviewers can *guess* at what a migration does;
 * this returns a reproducible verdict — same input, same answer, fail-closed on anything
 * unverifiable — so an agent reviewing a PR can quote a stable access delta instead of
 * approximating one. Read-only: the underlying git operations are `rev-parse`/`ls-tree`/`show`.
 */

import { sourcesAtRef, sourcesInWorktree } from '@aegiskit/cli';
import {
  type DeltaSummary,
  diffAccess,
  renderDeltaMarkdown,
  summarizeDeltas,
} from '@aegiskit/policy-diff';
import { buildRlsModel } from '@aegiskit/scanner';

export interface PolicyDiffResult {
  readonly summary: DeltaSummary;
  /** Markdown rendering (identical to the PR comment `aegis diff --format markdown` posts). */
  readonly markdown: string;
}

export function explainPolicyDiff(
  cwd: string,
  base: string,
  trustedFunctions: readonly string[] = [],
): PolicyDiffResult {
  const baseModel = buildRlsModel(sourcesAtRef(cwd, base));
  const headModel = buildRlsModel(sourcesInWorktree(cwd));
  const deltas = diffAccess(baseModel, headModel, { trustedFunctions });
  return {
    summary: summarizeDeltas(deltas),
    markdown: renderDeltaMarkdown(deltas, { baseRef: base, headRef: 'working tree' }),
  };
}
