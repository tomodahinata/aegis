---
"@aegiskit/scanner": patch
---

scanner: point rule docs links and the SARIF `informationUri` at the live coverage matrix instead of the unregistered `aegis.dev` domain, which did not resolve. Every finding's `Docs:` link and the SARIF report now reach a real page. The canonical project URL is centralized as `PROJECT_URL` so it can never drift across reporters again.
