// VULN: a cross-window `message` handler trusts event.data without checking event.origin. Any page that
// embeds this widget in an iframe (or opens it as a popup) can postMessage arbitrary commands to it.
const state: Record<string, unknown> = {};

export function listen(): void {
  window.addEventListener('message', (event) => {
    const { key, value } = event.data;
    state[key] = value;
  });
}
