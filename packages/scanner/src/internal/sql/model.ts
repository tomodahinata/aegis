/**
 * Build a cross-file model of the Supabase access-control surface from migration SQL. RLS state is
 * aggregated ACROSS files (a table created in one migration may have RLS enabled in another), so rules
 * evaluate the final, whole-project picture. Pure regex extraction over the lexer's statements — a
 * focused model of exactly the constructs the RLS rules need, not a SQL parser.
 */

import { OWNERSHIP_COLUMN_PATTERN, OWNERSHIP_COLUMNS } from '../ownership-columns';
import { splitStatements } from './lexer';
import { classifyPredicate, extractClauseBody, type PredicateClass } from './predicate';

export interface SqlLocation {
  readonly file: string;
  readonly line: number;
  readonly column: number;
}

export type PolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete';

export interface PolicyInfo {
  readonly table: string;
  readonly command: PolicyCommand;
  /** RESTRICTIVE policies AND-narrow access (a deny refinement); PERMISSIVE (default) grant it. */
  readonly restrictive: boolean;
  readonly roles: readonly string[];
  readonly usingTrue: boolean;
  readonly hasCheck: boolean;
  readonly checkTrue: boolean;
  /** Raw expression inside `USING (…)`, or undefined if absent. The authoritative predicate capture. */
  readonly usingExpr?: string;
  /** Raw expression inside `WITH CHECK (…)`, or undefined if absent. */
  readonly checkExpr?: string;
  /** Semantic class of the USING predicate (`absent` when there is no USING clause). */
  readonly usingClass: PredicateClass;
  /** Semantic class of the WITH CHECK predicate (`absent` when there is no WITH CHECK clause). */
  readonly checkClass: PredicateClass;
  /**
   * Whether the policy's table carries an ownership column (user_id/tenant_id/org_id/…). Always resolved
   * on the model RETURNED by `buildRlsModel`: the `false` initializer is only a transient value during
   * the build, overwritten in the finalization pass once every CREATE TABLE / ADD COLUMN is seen.
   */
  readonly tableHasOwnershipColumn: boolean;
  readonly loc: SqlLocation;
}

export interface GrantInfo {
  readonly table: string;
  readonly roles: readonly string[];
  readonly loc: SqlLocation;
}

export interface FunctionInfo {
  readonly name: string;
  readonly searchPathPinned: boolean;
  readonly loc: SqlLocation;
}

export interface TableInfo {
  readonly name: string;
  readonly rlsEnabled: boolean;
  /** Whether the table declares an ownership column (user_id/tenant_id/org_id/…). */
  readonly hasOwnershipColumn: boolean;
  readonly loc: SqlLocation;
}

export interface RlsModel {
  readonly tables: ReadonlyMap<string, TableInfo>;
  readonly policies: readonly PolicyInfo[];
  readonly grants: readonly GrantInfo[];
  readonly securityDefinerFunctions: readonly FunctionInfo[];
}

export interface SqlSource {
  readonly path: string;
  readonly text: string;
}

interface MutableTable {
  name: string;
  rlsEnabled: boolean;
  hasOwnershipColumn: boolean;
  loc: SqlLocation;
}

/** A policy under construction: `tableHasOwnershipColumn` is set in the finalization pass below. */
interface MutablePolicy {
  /** Policy name (normalized), unique per table — the identity key for DROP/ALTER. */
  name: string;
  table: string;
  command: PolicyCommand;
  restrictive: boolean;
  roles: readonly string[];
  usingTrue: boolean;
  hasCheck: boolean;
  checkTrue: boolean;
  usingExpr?: string;
  checkExpr?: string;
  usingClass: PredicateClass;
  checkClass: PredicateClass;
  tableHasOwnershipColumn: boolean;
  loc: SqlLocation;
}

/** Schema-qualified object name → its parts. Unqualified ⇒ schema 'public' (the PostgreSQL default). */
function parseQualified(raw: string): { schema: string; name: string } {
  const cleaned = raw.replace(/"/g, '');
  const dot = cleaned.indexOf('.');
  return dot === -1
    ? { schema: 'public', name: cleaned }
    : { schema: cleaned.slice(0, dot), name: cleaned.slice(dot + 1) };
}

/** Normalize a policy name for keying (strip quotes, lowercase) — PG names are unique per table. */
function normalizeName(raw: string): string {
  return raw.replace(/"/g, '').toLowerCase();
}

/**
 * Identity key for a policy: its table plus its (normalized) name.
 * NUL (`\x00`) is the delimiter because it can never appear in a SQL
 * identifier, so the two parts can be joined without collision or escaping.
 */
function policyKey(table: string, name: string): string {
  return `${table}\x00${normalizeName(name)}`;
}

const CREATE_TABLE =
  /^create\s+(?:unlogged\s+|global\s+|local\s+|temp\s+|temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w".]+)/i;
const DROP_TABLE = /^drop\s+table\s+(?:if\s+exists\s+)?([\w".]+)/i;
const ENABLE_RLS =
  /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+(?:enable|force)\s+row\s+level\s+security/i;
const ALTER_ADD_COLUMN =
  /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?([\w"]+)/i;
// Policy statements capture the NAME (group 1) and the table (group 2) so the model can key policies by
// identity and apply CREATE/DROP/ALTER in migration order (final-state semantics).
const CREATE_POLICY = /^create\s+policy\s+("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const DROP_POLICY = /^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const ALTER_POLICY = /^alter\s+policy\s+("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const CREATE_FUNCTION = /^create\s+(?:or\s+replace\s+)?function\s+([\w".]+)/i;
const DROP_FUNCTION = /^drop\s+function\s+(?:if\s+exists\s+)?([\w".]+)/i;
const GRANT = /^grant\s+/i;

function policyCommand(text: string): PolicyCommand {
  const m = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(text);
  // Map the captured keyword to the union explicitly — no cast, so the type can never silently drift
  // out of sync with the regex alternation.
  switch (m?.[1]?.toLowerCase()) {
    case 'select':
      return 'select';
    case 'insert':
      return 'insert';
    case 'update':
      return 'update';
    case 'delete':
      return 'delete';
    default:
      return 'all';
  }
}

function policyRoles(text: string): string[] {
  const m = /\bto\s+([\w\s,"]+?)(?=\s+using\b|\s+with\b|\s*$)/i.exec(text);
  return m?.[1]
    ? m[1]
        .split(',')
        .map((r) => r.trim().replace(/"/g, '').toLowerCase())
        .filter(Boolean)
    : [];
}

function functionPrelude(text: string): string {
  const body = /\bas\s+(\$[A-Za-z0-9_]*\$|')/i.exec(text);
  return body ? text.slice(0, body.index) : text;
}

function grantRoles(text: string): string[] {
  const m = /\bto\s+([\w\s,"]+?)(?:\s+with\s+grant\b|;|$)/i.exec(text);
  return m?.[1]
    ? m[1]
        .split(',')
        .map((r) => r.trim().replace(/"/g, '').toLowerCase())
        .filter(Boolean)
    : [];
}

/** Is this GRANT on a TABLE (vs function/sequence/schema, which are out of scope for RLS)? */
function grantTable(text: string): string | undefined {
  if (
    /\bon\s+(?:all\s+)?(?:functions?|sequences?|schema|routines?|types?|languages?)\b/i.test(text)
  ) {
    return undefined;
  }
  if (/\bon\s+all\s+tables\s+in\s+schema\b/i.test(text)) {
    return '*'; // a schema-wide table grant
  }
  const m = /\bon\s+(?:table\s+)?([\w".]+)\s+to\b/i.exec(text);
  if (!m?.[1]) {
    return undefined;
  }
  const { schema, name } = parseQualified(m[1]);
  return schema === 'public' ? name : undefined;
}

/** Apply `ALTER POLICY … [USING (…)] [WITH CHECK (…)] [TO roles]` to an existing policy, in place. */
function applyAlterPolicy(policy: MutablePolicy, text: string, loc: SqlLocation): void {
  const usingExpr = extractClauseBody(text, 'using');
  if (usingExpr !== undefined) {
    policy.usingExpr = usingExpr;
    policy.usingClass = classifyPredicate(usingExpr);
    policy.usingTrue = /\busing\s*\(\s*true\s*\)/i.test(text);
  }
  const checkExpr = extractClauseBody(text, 'with check');
  if (checkExpr !== undefined) {
    policy.checkExpr = checkExpr;
    policy.checkClass = classifyPredicate(checkExpr);
    policy.hasCheck = true;
    policy.checkTrue = /\bwith\s+check\s*\(\s*true\s*\)/i.test(text);
  }
  const roles = policyRoles(text);
  if (roles.length > 0) {
    policy.roles = roles;
  }
  policy.loc = loc;
}

interface FunctionRecord {
  searchPathPinned: boolean;
  isDefiner: boolean;
  loc: SqlLocation;
}

export function buildRlsModel(sources: readonly SqlSource[]): RlsModel {
  const tables = new Map<string, MutableTable>();
  // Policies and functions are keyed by identity and mutated in MIGRATION ORDER, so the model reflects
  // the FINAL schema state: a later DROP/ALTER/CREATE-OR-REPLACE supersedes an earlier definition rather
  // than accumulating beside it. Without this, an incremental history (drop + recreate, common in real
  // projects) leaves stale duplicates → false positives on policies/functions that no longer exist.
  const policies = new Map<string, MutablePolicy>();
  const functions = new Map<string, FunctionRecord>();
  const grants: GrantInfo[] = [];

  for (const source of sources) {
    for (const stmt of splitStatements(source.text)) {
      const loc: SqlLocation = { file: source.path, line: stmt.line, column: stmt.column };
      const text = stmt.text;

      const createTable = CREATE_TABLE.exec(text);
      if (createTable?.[1]) {
        const { schema, name } = parseQualified(createTable[1]);
        // Skip TEMP tables (session-local, RLS N/A) and partitions (inherit the parent's RLS).
        const isTransient =
          /\b(?:temp|temporary)\s+table\b/i.test(text) || /\bpartition\s+of\b/i.test(text);
        if (schema === 'public' && !isTransient && !tables.has(name)) {
          tables.set(name, {
            name,
            rlsEnabled: false,
            hasOwnershipColumn: OWNERSHIP_COLUMN_PATTERN.test(text),
            loc,
          });
        }
        continue;
      }
      const dropTable = DROP_TABLE.exec(text);
      if (dropTable?.[1]) {
        tables.delete(parseQualified(dropTable[1]).name);
        continue;
      }
      const enableRls = ENABLE_RLS.exec(text);
      if (enableRls?.[1]) {
        const { schema, name } = parseQualified(enableRls[1]);
        if (schema === 'public') {
          const existing = tables.get(name);
          if (existing) {
            existing.rlsEnabled = true;
          }
        }
        continue;
      }
      const addColumn = ALTER_ADD_COLUMN.exec(text);
      if (addColumn?.[1] && addColumn[2]) {
        const { schema, name } = parseQualified(addColumn[1]);
        const column = addColumn[2].replace(/"/g, '').toLowerCase();
        if (schema === 'public' && OWNERSHIP_COLUMNS.has(column)) {
          const existing = tables.get(name);
          if (existing) {
            existing.hasOwnershipColumn = true;
          }
        }
        continue;
      }
      const createPolicy = CREATE_POLICY.exec(text);
      if (createPolicy?.[1] && createPolicy[2]) {
        const { schema, name: table } = parseQualified(createPolicy[2]);
        if (schema === 'public') {
          const usingExpr = extractClauseBody(text, 'using');
          const checkExpr = extractClauseBody(text, 'with check');
          const policyName = normalizeName(createPolicy[1]);
          policies.set(policyKey(table, policyName), {
            name: policyName,
            table,
            command: policyCommand(text),
            restrictive: /\bas\s+restrictive\b/i.test(text),
            roles: policyRoles(text),
            usingTrue: /\busing\s*\(\s*true\s*\)/i.test(text),
            hasCheck: /\bwith\s+check\b/i.test(text),
            checkTrue: /\bwith\s+check\s*\(\s*true\s*\)/i.test(text),
            usingClass: classifyPredicate(usingExpr),
            checkClass: classifyPredicate(checkExpr),
            // Resolved in the finalization pass once every table is known (cross-file/order-safe).
            tableHasOwnershipColumn: false,
            loc,
            ...(usingExpr !== undefined ? { usingExpr } : {}),
            ...(checkExpr !== undefined ? { checkExpr } : {}),
          });
        }
        continue;
      }
      const dropPolicy = DROP_POLICY.exec(text);
      if (dropPolicy?.[1] && dropPolicy[2]) {
        const { schema, name: table } = parseQualified(dropPolicy[2]);
        if (schema === 'public') {
          policies.delete(policyKey(table, dropPolicy[1]));
        }
        continue;
      }
      const alterPolicy = ALTER_POLICY.exec(text);
      if (alterPolicy?.[1] && alterPolicy[2]) {
        const { schema, name: table } = parseQualified(alterPolicy[2]);
        if (schema === 'public') {
          const existing = policies.get(policyKey(table, alterPolicy[1]));
          if (existing) {
            applyAlterPolicy(existing, text, loc);
          }
        }
        continue;
      }
      const createFn = CREATE_FUNCTION.exec(text);
      if (createFn?.[1]) {
        const prelude = functionPrelude(text);
        // Last definition wins (CREATE OR REPLACE): keyed by name so a later redefinition — e.g. one that
        // ADDS `SET search_path` — supersedes the earlier one instead of lingering as a false positive.
        functions.set(parseQualified(createFn[1]).name, {
          isDefiner: /\bsecurity\s+definer\b/i.test(prelude),
          // Accept `SET search_path = …` and pg_dump's `SET "search_path" TO …` (quoted).
          searchPathPinned: /\bset\s+"?search_path"?/i.test(prelude),
          loc,
        });
        continue;
      }
      const dropFn = DROP_FUNCTION.exec(text);
      if (dropFn?.[1]) {
        functions.delete(parseQualified(dropFn[1]).name);
        continue;
      }
      if (GRANT.test(text)) {
        const table = grantTable(text);
        if (table !== undefined) {
          grants.push({ table, roles: grantRoles(text), loc });
        }
      }
    }
  }

  // Finalization: resolve each policy's table ownership-column flag now that every CREATE TABLE / ADD
  // COLUMN across all files has been seen (the table may be defined in a different file or later).
  for (const policy of policies.values()) {
    policy.tableHasOwnershipColumn = tables.get(policy.table)?.hasOwnershipColumn ?? false;
  }

  const securityDefinerFunctions: FunctionInfo[] = [];
  for (const [name, fn] of functions) {
    if (fn.isDefiner) {
      securityDefinerFunctions.push({ name, searchPathPinned: fn.searchPathPinned, loc: fn.loc });
    }
  }

  return { tables, policies: [...policies.values()], grants, securityDefinerFunctions };
}
