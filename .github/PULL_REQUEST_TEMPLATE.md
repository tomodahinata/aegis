<!-- Keep the title in Conventional Commits form, e.g. `feat(scanner): …` — the commitlint check
     enforces it. A change without a test is incomplete (see CONTRIBUTING / CLAUDE.md). -->

## Summary

<!-- What does this change and why? Link any issue with `Closes #123`. -->

## Type of change

- [ ] `fix` — bug fix
- [ ] `feat` — new capability
- [ ] `refactor` / `perf` — no behavior change
- [ ] `docs` / `test` / `ci` / `chore`

## Security considerations

<!-- Does this touch a security decision (authz, validation, headers/CSP, secrets, a scanner rule)?
     Note the fail-secure behavior. Write "none" only if you are sure. -->

## Verification

- [ ] `pnpm verify` passes locally (build · typecheck · test · lint)
- [ ] Added/updated co-located `*.test.ts`; new branches are covered
- [ ] Coverage thresholds in `vitest.config.ts` bumped if a package's coverage improved (ratchet)
- [ ] No secrets, tokens, or real credentials added (the scanner's fake corpus excepted)
- [ ] Docs/README updated if public behavior or surface changed
