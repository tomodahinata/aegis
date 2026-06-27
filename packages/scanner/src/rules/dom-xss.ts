import { ts } from '../internal/ast';
import { assignmentSink, methodCallSink } from '../internal/taint-sinks';
import { docsUrlFor } from '../rule';
import { defineTaintRule } from './taint-rule';

/**
 * Only a `Document`'s `.write(...)` / `.writeln(...)` parses its argument as HTML — every other
 * `.write()`/`.writeln()` in the wild is a Node stream/socket/response/file write (`process.stderr.write`,
 * `res.write`, a `WriteStream`) whose argument never touches the DOM. Constraining the sink to a
 * `document`-shaped receiver is what keeps it from firing on those — a real-world false positive was a
 * CLI's `process.stderr.write`. We accept every form that is provably a `Document`: the global `document`,
 * a qualified `…document` (`win.document`, `iframe.contentWindow.document`), the computed `obj['document']`,
 * and `node.ownerDocument` (which the DOM spec defines as always a `Document`). The matched name is the
 * literal `document`/`ownerDocument`, never an arbitrary string, so no Node-stream receiver slips through.
 */
const DOCUMENT_RECEIVER_NAMES: ReadonlySet<string> = new Set(['document', 'ownerDocument']);
const isDocumentReceiver = (receiver: ts.Expression): boolean =>
  (ts.isIdentifier(receiver) && DOCUMENT_RECEIVER_NAMES.has(receiver.text)) ||
  (ts.isPropertyAccessExpression(receiver) && DOCUMENT_RECEIVER_NAMES.has(receiver.name.text)) ||
  (ts.isElementAccessExpression(receiver) &&
    ts.isStringLiteralLike(receiver.argumentExpression) &&
    DOCUMENT_RECEIVER_NAMES.has(receiver.argumentExpression.text));

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
        isDocumentReceiver,
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
