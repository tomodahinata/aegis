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

/**
 * Schemas whose POLICIES the model captures. `public` is the app schema every rule reasons about;
 * `storage` is Supabase Storage (`storage.objects` — the access surface of bucket uploads, and a
 * notorious real-world leak vector: 40% of a 300-repo public corpus ships storage policies).
 * Policies on any OTHER schema are recorded as `uninterpreted` rather than silently dropped, so a
 * consumer that diffs two models can fail closed instead of reporting a false "no change".
 *
 * Scope note: only POLICIES (and their identity) are modeled for `storage` — table state stays
 * public-only because `storage.objects` is platform-managed (RLS pre-enabled, no CREATE TABLE in
 * user migrations). Existing scan rules deliberately skip non-`public` policies (their zero-FP
 * calibration is for app tables; e.g. `WITH CHECK (true)` on a public-upload bucket is idiomatic).
 */
export type PolicySchema = 'public' | 'storage';

export interface PolicyInfo {
  /** Policy name (normalized: quotes stripped, lowercased) — the identity PostgreSQL keys DROP/ALTER by. */
  readonly name: string;
  /** Schema of the policy's table (see {@link PolicySchema}). */
  readonly schema: PolicySchema;
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
  /**
   * The first ownership column the table DECLARES (e.g. `user_id`), lowercased — the concrete column a
   * suggested owner-scoped policy binds to. Usually present when `hasOwnershipColumn` is true, but may be
   * absent even then if the only match was an FK `REFERENCES()` to another table (the RLS rule falls back
   * to a canonical name). Advisory only: when a table carries several, the first seen is used; the reader
   * adapts the suggestion to their model.
   */
  readonly ownershipColumn?: string;
  readonly loc: SqlLocation;
}

/**
 * An access-relevant statement the model could NOT interpret. Recorded so a consumer comparing two
 * models (the policy diff) can fail CLOSED — "we saw an RLS/policy/grant statement we don't
 * understand here" — instead of silently reporting "no access change". Deliberately narrow: only
 * statement families that can change ACCESS are recorded (RLS state, policies, grants); ordinary
 * unrecognized DDL (constraints, column types, …) is not, or every migration would flag.
 */
export interface UninterpretedStatement {
  readonly kind: // Contains `ROW LEVEL SECURITY` but matched no handler (e.g. `NO FORCE ROW LEVEL SECURITY`).
    | 'rls-statement'
    // A CREATE/ALTER/DROP POLICY whose name/table failed to parse (exotic quoting).
    | 'policy-statement'
    // A policy statement on a schema outside {@link PolicySchema} (e.g. `auth`, `realtime`).
    | 'policy-on-unmodeled-schema'
    // ALTER POLICY (incl. RENAME) targeting a policy the model never saw created.
    | 'alter-policy-unknown-target'
    // A REVOKE of specific privileges: the model tracks grant PRESENCE, not per-privilege state, so
    // the grant is conservatively RETAINED (fail-secure for the leak rules) and the statement recorded.
    | 'revoke-partial';
  /** Unqualified table name, when the statement names one. */
  readonly table?: string;
  readonly loc: SqlLocation;
}

export interface RlsModel {
  readonly tables: ReadonlyMap<string, TableInfo>;
  readonly policies: readonly PolicyInfo[];
  readonly grants: readonly GrantInfo[];
  readonly securityDefinerFunctions: readonly FunctionInfo[];
  /** Access-relevant statements the model could not interpret — consumers must treat these fail-closed. */
  readonly uninterpreted: readonly UninterpretedStatement[];
}

export interface SqlSource {
  readonly path: string;
  readonly text: string;
}

interface MutableTable {
  name: string;
  rlsEnabled: boolean;
  hasOwnershipColumn: boolean;
  ownershipColumn?: string;
  loc: SqlLocation;
}

/**
 * The first ownership column the statement DECLARES, lowercased, or undefined. Columns that appear only
 * inside a `REFERENCES(...)` clause are ignored: they name another table's column (an FK target), not one
 * this table has, so binding a suggested policy to one would emit SQL referencing a column that does not
 * exist here. Presence detection (`hasOwnershipColumn`) stays on the raw text so RLS-gap detection is
 * unchanged; only the concrete column chosen for the advisory suggestion is refined.
 */
function firstOwnershipColumn(text: string): string | undefined {
  const withoutForeignRefs = text.replace(/\breferences\b[^(]*\([^)]*\)/gi, ' ');
  return OWNERSHIP_COLUMN_PATTERN.exec(withoutForeignRefs)?.[0]?.toLowerCase();
}

/** A policy under construction: `tableHasOwnershipColumn` is set in the finalization pass below. */
interface MutablePolicy {
  /** Policy name (normalized), unique per table — the identity key for DROP/ALTER. */
  name: string;
  schema: PolicySchema;
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
 * Identity key for a policy: its schema, table, and (normalized) name.
 * NUL (`\x00`) is the delimiter because it can never appear in a SQL
 * identifier, so the parts can be joined without collision or escaping.
 * The schema is part of the key so a policy on `storage.objects` can never
 * collide with one on a user table that happens to be named `objects`.
 */
function policyKey(schema: string, table: string, name: string): string {
  return `${schema}\x00${table}\x00${normalizeName(name)}`;
}

/** Is `schema` one the model captures policies for? Narrows to the {@link PolicySchema} union. */
function isPolicySchema(schema: string): schema is PolicySchema {
  return schema === 'public' || schema === 'storage';
}

const CREATE_TABLE =
  /^create\s+(?:unlogged\s+|global\s+|local\s+|temp\s+|temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w".]+)/i;
const DROP_TABLE = /^drop\s+table\s+(?:if\s+exists\s+)?([\w".]+)/i;
const ENABLE_RLS =
  /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+(?:enable|force)\s+row\s+level\s+security/i;
// The DISABLE counterpart. Unparsed, a `DISABLE ROW LEVEL SECURITY` leaves the model claiming RLS is
// on — the exact fail-open a policy DIFF must not have (base "enabled" vs head "disabled" would read
// as no change). `NO FORCE` is deliberately NOT here: it only stops applying RLS to the table OWNER;
// regular roles stay policy-scoped, so treating it as a disable would fabricate a widening. It falls
// through to the `rls-statement` uninterpreted net instead (fail closed, never fail wrong).
const DISABLE_RLS = /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+disable\s+row\s+level\s+security/i;
const ALTER_ADD_COLUMN =
  /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?([\w"]+)/i;
// Policy statements capture the NAME (group 1) and the table (group 2) so the model can key policies by
// identity and apply CREATE/DROP/ALTER in migration order (final-state semantics).
const CREATE_POLICY = /^create\s+policy\s+("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const DROP_POLICY = /^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
// RENAME is matched BEFORE the generic ALTER_POLICY: the generic handler's `TO roles` capture would
// otherwise read `RENAME TO new_name` as a roles list and corrupt the policy's roles.
const ALTER_POLICY_RENAME =
  /^alter\s+policy\s+("[^"]+"|[\w-]+)\s+on\s+([\w".]+)\s+rename\s+to\s+("[^"]+"|[\w-]+)/i;
const ALTER_POLICY = /^alter\s+policy\s+("[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const CREATE_FUNCTION = /^create\s+(?:or\s+replace\s+)?function\s+([\w".]+)/i;
const DROP_FUNCTION = /^drop\s+function\s+(?:if\s+exists\s+)?([\w".]+)/i;
const GRANT = /^grant\s+/i;
const REVOKE = /^revoke\s+/i;
// Only a REVOKE of ALL privileges removes a grant from the model: the model tracks grant PRESENCE,
// not per-privilege state, so removing on a partial revoke (`REVOKE SELECT …` when INSERT/UPDATE may
// remain granted) would fail OPEN for the leak rules. Partial revokes are recorded uninterpreted.
const REVOKE_ALL = /^revoke\s+(?:grant\s+option\s+for\s+)?all(?:\s+privileges)?\b/i;
// Statement families the uninterpreted nets key on (see UninterpretedStatement).
const MENTIONS_RLS = /\brow\s+level\s+security\b/i;
const MENTIONS_POLICY = /^(?:create|alter|drop)\s+policy\b/i;

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

/** Roles named after `FROM` in a REVOKE (the GRANT counterpart names them after `TO`). */
function revokeRoles(text: string): string[] {
  const m = /\bfrom\s+([\w\s,"]+?)(?:\s+granted\s+by\b|\s+cascade\b|\s+restrict\b|;|\s*$)/i.exec(
    text,
  );
  return m?.[1]
    ? m[1]
        .split(',')
        .map((r) => r.trim().replace(/"/g, '').toLowerCase())
        .filter(Boolean)
    : [];
}

/** Is this REVOKE on a TABLE (vs function/sequence/schema — out of scope)? Mirrors `grantTable`. */
function revokeTable(text: string): string | undefined {
  if (
    /\bon\s+(?:all\s+)?(?:functions?|sequences?|schema|routines?|types?|languages?)\b/i.test(text)
  ) {
    return undefined;
  }
  if (/\bon\s+all\s+tables\s+in\s+schema\b/i.test(text)) {
    return '*';
  }
  const m = /\bon\s+(?:table\s+)?([\w".]+)\s+from\b/i.exec(text);
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

/** A grant under construction: roles are mutable so a later REVOKE ALL can remove them (final state). */
interface MutableGrant {
  table: string;
  roles: string[];
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
  const grants: MutableGrant[] = [];
  const uninterpreted: UninterpretedStatement[] = [];

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
          const ownershipColumn = firstOwnershipColumn(text);
          tables.set(name, {
            name,
            rlsEnabled: false,
            // Presence stays on the raw text (detection unchanged); the concrete column may still be
            // undefined if the only match was an FK reference — the RLS rule falls back defensively then.
            hasOwnershipColumn: OWNERSHIP_COLUMN_PATTERN.test(text),
            loc,
            ...(ownershipColumn !== undefined ? { ownershipColumn } : {}),
          });
        }
        continue;
      }
      const dropTable = DROP_TABLE.exec(text);
      if (dropTable?.[1]) {
        const { schema, name } = parseQualified(dropTable[1]);
        // Schema-checked: `DROP TABLE storage.foo` must not delete a public table named `foo`.
        if (schema === 'public') {
          tables.delete(name);
        }
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
      const disableRls = DISABLE_RLS.exec(text);
      if (disableRls?.[1]) {
        const { schema, name } = parseQualified(disableRls[1]);
        if (schema === 'public') {
          const existing = tables.get(name);
          if (existing) {
            existing.rlsEnabled = false;
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
            existing.ownershipColumn ??= column; // keep the first; a CREATE-TABLE column takes precedence
          }
        }
        continue;
      }
      const createPolicy = CREATE_POLICY.exec(text);
      if (createPolicy?.[1] && createPolicy[2]) {
        const { schema, name: table } = parseQualified(createPolicy[2]);
        if (isPolicySchema(schema)) {
          const usingExpr = extractClauseBody(text, 'using');
          const checkExpr = extractClauseBody(text, 'with check');
          const policyName = normalizeName(createPolicy[1]);
          policies.set(policyKey(schema, table, policyName), {
            name: policyName,
            schema,
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
        } else {
          uninterpreted.push({ kind: 'policy-on-unmodeled-schema', table, loc });
        }
        continue;
      }
      const dropPolicy = DROP_POLICY.exec(text);
      if (dropPolicy?.[1] && dropPolicy[2]) {
        const { schema, name: table } = parseQualified(dropPolicy[2]);
        if (isPolicySchema(schema)) {
          policies.delete(policyKey(schema, table, dropPolicy[1]));
        } else {
          uninterpreted.push({ kind: 'policy-on-unmodeled-schema', table, loc });
        }
        continue;
      }
      // RENAME before the generic ALTER: the generic handler's roles capture would misread `RENAME TO
      // new_name` as a `TO` roles list. A rename re-keys the policy so a later DROP/ALTER by the NEW
      // name finds it — otherwise the old entry lingers as a stale duplicate (fail open for a differ).
      const renamePolicy = ALTER_POLICY_RENAME.exec(text);
      if (renamePolicy?.[1] && renamePolicy[2] && renamePolicy[3]) {
        const { schema, name: table } = parseQualified(renamePolicy[2]);
        if (isPolicySchema(schema)) {
          const existing = policies.get(policyKey(schema, table, renamePolicy[1]));
          if (existing) {
            policies.delete(policyKey(schema, table, renamePolicy[1]));
            existing.name = normalizeName(renamePolicy[3]);
            existing.loc = loc;
            policies.set(policyKey(schema, table, existing.name), existing);
          } else {
            uninterpreted.push({ kind: 'alter-policy-unknown-target', table, loc });
          }
        } else {
          uninterpreted.push({ kind: 'policy-on-unmodeled-schema', table, loc });
        }
        continue;
      }
      const alterPolicy = ALTER_POLICY.exec(text);
      if (alterPolicy?.[1] && alterPolicy[2]) {
        const { schema, name: table } = parseQualified(alterPolicy[2]);
        if (isPolicySchema(schema)) {
          const existing = policies.get(policyKey(schema, table, alterPolicy[1]));
          if (existing) {
            applyAlterPolicy(existing, text, loc);
          } else {
            uninterpreted.push({ kind: 'alter-policy-unknown-target', table, loc });
          }
        } else {
          uninterpreted.push({ kind: 'policy-on-unmodeled-schema', table, loc });
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
        continue;
      }
      if (REVOKE.test(text)) {
        const table = revokeTable(text);
        if (table !== undefined) {
          if (REVOKE_ALL.test(text)) {
            // Final-state semantics: strip the revoked roles from matching prior grants. A schema-wide
            // revoke (`… ON ALL TABLES IN SCHEMA public`) covers per-table grants too; the converse is
            // deliberately NOT true — a single-table revoke never touches a schema-wide (`*`) grant,
            // because that grant still applies to every OTHER table (removing the role there would fail
            // OPEN for the leak rules; keeping it is the fail-secure over-approximation).
            const revoked = new Set(revokeRoles(text));
            for (const grant of grants) {
              if (table === '*' || grant.table === table) {
                grant.roles = grant.roles.filter((role) => !revoked.has(role));
              }
            }
          } else {
            uninterpreted.push({ kind: 'revoke-partial', table, loc });
          }
        }
        continue;
      }
      // Fail-closed nets: an access-relevant statement that matched NO handler above is recorded, so a
      // consumer diffing two models can flag "unrecognized RLS/policy statement" instead of silently
      // treating the migration as a no-op. Everything else (constraints, indexes, …) stays unrecorded.
      if (MENTIONS_RLS.test(text)) {
        uninterpreted.push({ kind: 'rls-statement', loc });
      } else if (MENTIONS_POLICY.test(text)) {
        uninterpreted.push({ kind: 'policy-statement', loc });
      }
    }
  }

  // Finalization: resolve each policy's table ownership-column flag now that every CREATE TABLE / ADD
  // COLUMN across all files has been seen (the table may be defined in a different file or later).
  // Schema-gated: a `storage.objects` policy must never resolve against a public table that happens
  // to be named `objects` — non-public policies always carry `false` (their tables are not modeled).
  for (const policy of policies.values()) {
    policy.tableHasOwnershipColumn =
      policy.schema === 'public' ? (tables.get(policy.table)?.hasOwnershipColumn ?? false) : false;
  }

  const securityDefinerFunctions: FunctionInfo[] = [];
  for (const [name, fn] of functions) {
    if (fn.isDefiner) {
      securityDefinerFunctions.push({ name, searchPathPinned: fn.searchPathPinned, loc: fn.loc });
    }
  }

  return {
    tables,
    policies: [...policies.values()],
    // A grant whose every role was revoked no longer grants anything — drop it from the final model.
    grants: grants.filter((grant) => grant.roles.length > 0),
    securityDefinerFunctions,
    uninterpreted,
  };
}
