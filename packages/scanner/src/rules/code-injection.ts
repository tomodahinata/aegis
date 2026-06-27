import { identCallSink, newExprSink } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/**
 * Dynamic code execution from input. `setTimeout`/`setInterval` are sinks only when their first
 * argument is a string — a function reference (the normal case) is not tainted, so it never matches.
 */
export const codeInjection = defineTaintRule({
  meta: {
    id: 'injection/code',
    title: 'Untrusted input reaches dynamic code execution',
    severity: 'BLOCKER',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('injection/code'),
  },
  appliesTo: (file) => /\b(?:eval|Function|setTimeout|setInterval)\s*\(/.test(file.text),
  spec: {
    sinks: [
      identCallSink('code.eval', 'code', 'reaches eval()', new Set(['eval']), [0]),
      identCallSink(
        'code.timer',
        'code',
        'reaches a string-bodied timer',
        new Set(['setTimeout', 'setInterval']),
        [0],
      ),
      newExprSink('code.function', 'code', 'reaches new Function()', new Set(['Function']), 'all'),
    ],
  },
  message:
    'Untrusted input reaches a dynamic code evaluator (eval / new Function) — it executes as code with full application privileges (code injection).',
  remediation:
    'Remove the dynamic evaluation. Parse data with JSON.parse, dispatch via a lookup table of known operations, and pass functions (not strings) to timers. Never evaluate input as code.',
  passDetail: 'Input reaching a dynamic evaluator is validated to a safe value first.',
});
