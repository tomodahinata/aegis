import { ts } from '../internal/ast';
import type { TaintSink } from '../internal/taint-descriptors';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

const FS_METHODS: ReadonlySet<string> = new Set([
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'createReadStream',
  'createWriteStream',
  'unlink',
  'unlinkSync',
  'readdir',
  'readdirSync',
  'open',
  'openSync',
  'rm',
  'rmSync',
]);
const PATH_BUILDERS: ReadonlySet<string> = new Set(['join', 'resolve']);

function builderName(call: ts.CallExpression): string | undefined {
  if (ts.isIdentifier(call.expression)) {
    return call.expression.text;
  }
  if (ts.isPropertyAccessExpression(call.expression)) {
    return call.expression.name.text;
  }
  return undefined;
}

/** Unwrap `path.join(base, x)` / `resolve(...)` to its segments so a tainted segment is seen. */
function pathSegments(arg: ts.Expression): readonly ts.Expression[] {
  if (ts.isCallExpression(arg)) {
    const name = builderName(arg);
    if (name && PATH_BUILDERS.has(name)) {
      return arg.arguments;
    }
  }
  return [arg];
}

/** First argument of an `fs.*` call (or a bare `readFile(...)`), unwrapped through path builders. */
const fsPathSink: TaintSink = {
  id: 'fs.path',
  category: 'fs-path',
  label: 'reaches a filesystem path',
  match: (node) => {
    if (!ts.isCallExpression(node)) {
      return [];
    }
    const callee = node.expression;
    const method = ts.isPropertyAccessExpression(callee)
      ? callee.name.text
      : ts.isIdentifier(callee)
        ? callee.text
        : undefined;
    if (!method || !FS_METHODS.has(method)) {
      return [];
    }
    const arg0 = node.arguments[0];
    return arg0 ? pathSegments(arg0) : [];
  },
};

export const pathTraversal = defineTaintRule({
  meta: {
    id: 'injection/path-traversal',
    title: 'Untrusted input builds a filesystem path',
    severity: 'HIGH',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: docsUrlFor('injection/path-traversal'),
  },
  appliesTo: (file) =>
    file.classification.context !== 'client' &&
    /\b(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|readdir|unlink|openSync|rmSync)\b/.test(
      file.text,
    ),
  spec: { sinks: [fsPathSink] },
  message:
    'Untrusted input is used to build a filesystem path — `../` sequences let an attacker read or overwrite files outside the intended directory (path traversal).',
  remediation:
    'Reduce the input to a single path segment with path.basename(...), then resolve against a fixed root and verify the result stays within it. Never join raw input into a path.',
  passDetail: 'A filesystem path derived from input is reduced with path.basename before use.',
});
