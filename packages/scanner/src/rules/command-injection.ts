import { identCallSink, methodCallSink } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/**
 * A shell string built from input. The safe form `execFile('cmd', [arg])` is naturally excluded: the
 * command is a constant first argument and the arguments arrive in an array (which the dataflow does
 * not treat as tainted), so only `exec(\`cmd ${input}\`)`-shaped sinks match.
 */
const SHELL_CALLS: ReadonlySet<string> = new Set([
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'execFile',
]);

export const commandInjection = defineTaintRule({
  meta: {
    id: 'injection/command',
    title: 'Untrusted input reaches a shell command',
    severity: 'BLOCKER',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('injection/command'),
  },
  appliesTo: (file) =>
    file.classification.context !== 'client' &&
    /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(/.test(file.text),
  spec: {
    sinks: [
      identCallSink('cmd.ident', 'shell', 'reaches a shell command', SHELL_CALLS, [0]),
      methodCallSink('cmd.method', 'shell', 'reaches a shell command', SHELL_CALLS, [0]),
    ],
  },
  message:
    'Untrusted input is passed to a shell command — an attacker can inject extra commands and execute arbitrary code on the server (command injection).',
  remediation:
    'Use execFile/spawn with the command and an ARRAY of arguments (never a shell string), and validate the input against an allowlist. Never interpolate input into a shell command.',
  passDetail: 'Input reaching a process call is validated before use.',
});
