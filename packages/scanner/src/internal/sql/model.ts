/**
 * Build a cross-file model of the Supabase access-control surface from migration SQL. RLS state is
 * aggregated ACROSS files (a table created in one migration may have RLS enabled in another), so rules
 * evaluate the final, whole-project picture. Pure regex extraction over the lexer's statements — a
 * focused model of exactly the constructs the RLS rules need, not a SQL parser.
 */

import { splitStatements } from './lexer';

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

const CREATE_TABLE =
  /^create\s+(?:unlogged\s+|global\s+|local\s+|temp\s+|temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w".]+)/i;
const DROP_TABLE = /^drop\s+table\s+(?:if\s+exists\s+)?([\w".]+)/i;
const ENABLE_RLS =
  /^alter\s+table\s+(?:only\s+)?([\w".]+)\s+(?:enable|force)\s+row\s+level\s+security/i;
const CREATE_POLICY = /^create\s+policy\s+(?:"[^"]+"|[\w-]+)\s+on\s+([\w".]+)/i;
const CREATE_FUNCTION = /^create\s+(?:or\s+replace\s+)?function\s+([\w".]+)/i;
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

export function buildRlsModel(sources: readonly SqlSource[]): RlsModel {
  const tables = new Map<string, MutableTable>();
  const policies: PolicyInfo[] = [];
  const grants: GrantInfo[] = [];
  const securityDefinerFunctions: FunctionInfo[] = [];

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
          tables.set(name, { name, rlsEnabled: false, loc });
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
      const createPolicy = CREATE_POLICY.exec(text);
      if (createPolicy?.[1]) {
        const { schema, name } = parseQualified(createPolicy[1]);
        if (schema === 'public') {
          policies.push({
            table: name,
            command: policyCommand(text),
            restrictive: /\bas\s+restrictive\b/i.test(text),
            roles: policyRoles(text),
            usingTrue: /\busing\s*\(\s*true\s*\)/i.test(text),
            hasCheck: /\bwith\s+check\b/i.test(text),
            checkTrue: /\bwith\s+check\s*\(\s*true\s*\)/i.test(text),
            loc,
          });
        }
        continue;
      }
      const createFn = CREATE_FUNCTION.exec(text);
      if (createFn?.[1]) {
        const prelude = functionPrelude(text);
        if (/\bsecurity\s+definer\b/i.test(prelude)) {
          securityDefinerFunctions.push({
            name: parseQualified(createFn[1]).name,
            // Accept `SET search_path = …` and pg_dump's `SET "search_path" TO …` (quoted).
            searchPathPinned: /\bset\s+"?search_path"?/i.test(prelude),
            loc,
          });
        }
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

  return { tables, policies, grants, securityDefinerFunctions };
}
