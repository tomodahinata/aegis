import { ts } from '../internal/ast';
import type { TaintSink } from '../internal/taint-descriptors';
import { methodCallSink } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/** Object-property names that carry raw SQL text into a Supabase RPC (vs. bound parameters). */
const RAW_SQL_KEYS = /^(?:sql|query|statement|stmt)$/i;

/**
 * `supabase.rpc(...)` is dangerous only when raw SQL text is built from input — NOT when input is
 * passed as a bound parameter. The discriminator is structural: a bound parameter arrives inside an
 * object literal (`{ tenant_id: x }`), which the dataflow does not treat as tainted, whereas raw SQL
 * arrives as a string argument or a `{ sql: … }` property. We surface exactly those positions.
 */
const rpcSink: TaintSink = {
  id: 'sql.rpc',
  category: 'sql',
  label: 'reaches supabase.rpc()',
  match: (node) => {
    if (
      !ts.isCallExpression(node) ||
      !ts.isPropertyAccessExpression(node.expression) ||
      node.expression.name.text !== 'rpc'
    ) {
      return [];
    }
    const dangerous: ts.Expression[] = [];
    for (const arg of node.arguments) {
      if (ts.isStringLiteralLike(arg)) {
        continue; // the function name
      }
      if (ts.isObjectLiteralExpression(arg)) {
        for (const property of arg.properties) {
          if (ts.isPropertyAssignment(property) && RAW_SQL_KEYS.test(property.name.getText())) {
            dangerous.push(property.initializer);
          }
        }
      } else {
        dangerous.push(arg);
      }
    }
    return dangerous;
  },
};

export const sqlInjection = defineTaintRule({
  meta: {
    id: 'injection/sql',
    title: 'Untrusted input reaches a SQL query',
    severity: 'BLOCKER',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('injection/sql'),
  },
  // `.rpc(` (Supabase), `.raw(`/`.unsafe(` (knex / postgres.js), `.query(` (node-postgres).
  appliesTo: (file) => /\.(?:rpc|raw|unsafe|query)\s*\(/.test(file.text),
  spec: {
    sinks: [
      rpcSink,
      methodCallSink(
        'sql.raw',
        'sql',
        'reaches a raw SQL call',
        new Set(['raw', 'unsafe', 'query']),
        [0],
      ),
    ],
  },
  message:
    'Untrusted input is concatenated into a SQL query — an attacker can read or modify other tenants’ rows, or drop tables (SQL injection).',
  remediation:
    'Never build SQL by string concatenation. Pass values as bound parameters (e.g. supabase.rpc("fn", { id }) or parameterized $1 placeholders), or validate to a strict type (Zod number/uuid/enum) first.',
  passDetail: 'Input reaching a SQL call is validated/parameterized before use.',
});
