import { assignmentSink, methodCallSink } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/**
 * Vanilla-DOM HTML sinks (`el.innerHTML = …`, `document.write(…)`, `insertAdjacentHTML`). These are
 * invisible to the JSX-only `xss/dangerous-html-unsanitized` rule, which owns `dangerouslySetInnerHTML`;
 * the two are disjoint so a node is never reported twice.
 */
export const domXss = defineTaintRule({
  meta: {
    id: 'xss/tainted-dom-sink',
    title: 'Untrusted input reaches a DOM HTML sink',
    severity: 'HIGH',
    owasp: 'A03:2021 Injection',
    docsUrl: docsUrlFor('xss/tainted-dom-sink'),
  },
  appliesTo: (file) => /innerHTML|outerHTML|insertAdjacentHTML|\.write(?:ln)?\s*\(/.test(file.text),
  spec: {
    sinks: [
      assignmentSink(
        'xss.innerHTML',
        'html',
        'assigned to innerHTML/outerHTML',
        new Set(['innerHTML', 'outerHTML']),
      ),
      methodCallSink(
        'xss.write',
        'html',
        'reaches document.write()',
        new Set(['write', 'writeln']),
        [0],
      ),
      // insertAdjacentHTML(position, html) — the HTML is the SECOND argument.
      methodCallSink(
        'xss.insertAdjacentHTML',
        'html',
        'reaches insertAdjacentHTML()',
        new Set(['insertAdjacentHTML']),
        [1],
      ),
    ],
  },
  message:
    'Untrusted input is written to the DOM as HTML — injected markup and scripts run in the user’s session (DOM-based XSS).',
  remediation:
    'Set textContent instead of innerHTML, or sanitize with DOMPurify.sanitize(...) before assigning. Never write raw user input as HTML.',
  passDetail: 'HTML written to the DOM is sanitized before assignment.',
});
