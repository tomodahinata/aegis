# @aegiskit/eslint-config

An ESLint flat-config preset that catches a few high-confidence Aegis security mistakes **at edit time**, complementing the (more precise) `aegis scan`. Implemented purely with core ESLint's `no-restricted-syntax` — no plugins, no custom rules — and tuned to be **false-positive-free**.

## Use

```js
// eslint.config.js
import aegis from '@aegiskit/eslint-config';

export default [
  // ...your config
  ...aegis,
];
```

## What it flags (all `error`, all unambiguous)

- A `NEXT_PUBLIC_`-prefixed env var whose name denotes a secret (`SECRET`/`SERVICE_ROLE`/`PRIVATE_KEY`/…) — it would ship in the client bundle.
- A hard-coded provider secret literal (`sk_live_`, `sk_test_`, `AKIA…`, `ghp_`).
- `eval(...)` and `new Function(...)`.

For the full, AST-aware set (CSP, rate limits, IDOR-class checks, etc.), run `aegis scan`.

## License

MIT
