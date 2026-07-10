# Releasing Aegis

How code becomes a published `@aegiskit/*` package. The whole pipeline is automated with
[Changesets](https://github.com/changesets/changesets); you never run `npm publish` by hand, and
**pushing to `main` does _not_ publish** — publishing is a deliberate, two-phase, human-gated step.

## The flow at a glance

```
 feature branch ──PR──▶ main
                         │  Release workflow (on every push to main)
                         ▼
         ┌───────────────────────────────────────────────┐
         │  changesets present?                           │
         │    yes → open/refresh the "Version Packages" PR │  ← phase 1: NO publish, just versions+CHANGELOGs
         │    no  → run `pnpm release` → publish to npm     │  ← phase 2: runs AFTER the Version PR merges
         └───────────────────────────────────────────────┘
                         │
                         ▼
      npm packages published with provenance (OIDC) + CycloneDX SBOM artifact
```

The **"Version Packages" PR is your publish button.** It accumulates every pending changeset into version
bumps and CHANGELOG entries. While it stays open, nothing is on npm. The moment you merge it, the next
`main` build finds no changesets left and runs the publish.

## Day-to-day: shipping a change

1. **Branch, code, test.** Direct pushes to `main` are blocked — open a PR (see
   [CONTRIBUTING.md](.github/CONTRIBUTING.md)).
2. **Add a changeset** for anything a consumer would notice:
   ```bash
   pnpm changeset      # choose packages + bump (patch/minor/major), write a consumer-facing summary
   ```
   Internal-only refactors need no changeset. **No changeset ⇒ nothing ships**, even after merge.
3. **Merge the PR** into `main` once its required checks are green.
4. The **Release** workflow opens or updates the **`chore(release): version packages`** PR. Review it —
   the diff is the exact set of version bumps and changelog text that will go public.
5. **Merge the Version PR when you want to release.** That triggers the publish:
   - `turbo run build` builds every package's `dist`,
   - `changeset publish` publishes only the packages whose version changed,
   - each artifact carries **npm provenance** (a signed attestation linking it to the commit + workflow run),
   - a **CycloneDX SBOM** of the full dependency tree is uploaded as a 90-day workflow artifact.

That's it. Version numbers, tags, CHANGELOGs, npm dist-tags, and provenance are all handled for you.

## What is and isn't published

Each package is versioned independently. `apps/*` and `@aegiskit/demo` are private and never publish
(`.changeset/config.json` `ignore`, and `"private": true`). A package only publishes when a changeset has
bumped its version — so a brand-new package sitting at `0.0.0` will not appear on npm until its first
changeset lands and its Version PR merges.

## Publishing auth — npm Trusted Publishing (OIDC, tokenless)

There is **no `NPM_TOKEN`**. The Release workflow authenticates to npm via **Trusted Publishing (OIDC)**:
npm verifies the workflow's own identity (repository + workflow filename), so there is no long-lived
token to leak, rotate, or expire. Provenance is generated automatically.

What makes it work:

- **`id-token: write`** on the Release workflow (the sole publish credential).
- **npm CLI ≥ 11.5.1** — the workflow runs `npm install -g npm@latest` before publishing so OIDC auth is
  reliable regardless of the npm bundled with Node.
- **A Trusted Publisher on each `@aegiskit/*` package** (npmjs.com → the package → *Settings → Trusted
  Publisher*), all pointing at the same identity:
  - Organization or user: **`tomodahinata`**
  - Repository: **`aegis`**
  - Workflow filename: **`release.yml`** (filename only, not the full path)
  - Environment: **(leave empty)**
  - Allowed action: **npm publish**

Adding a **new** package to the monorepo: npm can only configure a Trusted Publisher on a package that
already exists, so a brand-new package needs one bootstrap publish before it can go tokenless — publish
it once (locally with your npm login, or via a temporary token), then add its Trusted Publisher and it
joins the OIDC flow like the rest.

## Rollback

npm does not allow re-publishing a version, and unpublish is restricted (only within 72h and with no
dependents). So **fixing forward is the norm**: ship a new patch. If a published version is actively
dangerous, use `npm deprecate @aegiskit/<pkg>@<version> "reason — upgrade to <x>"` and cut the fix.

## Manual release (break-glass only)

The automated flow above is the only supported path. If CI is down and a security fix must ship:

```bash
pnpm verify                     # build + typecheck + test + lint must pass
pnpm changeset version          # apply pending changesets locally
pnpm release                    # turbo build + changeset publish (needs a valid NPM_TOKEN in env)
```

Then push the version commit + tags through a PR. Prefer waiting for CI whenever possible — the automated
path is what produces provenance and the SBOM.
