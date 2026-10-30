# Dependency management rule — lexdocia-collecte-crypto

> Language: English. Binding for every change in this repository. Referenced from `CLAUDE.md` so that it is read systematically.
> This package is consumed by `lexdocia-collect` (portal, API) and `piecemaster`: a dependency added here is shipped to the lawyer's
> browser and desktop app, so the bar is higher than elsewhere.

## The rule

**Every time a library is introduced, removed, or its version is updated (including Dependabot PRs and lockfile-only bumps),
[third-party-libraries.md](third-party-libraries.md) must be updated in the same PR.**

For a new direct dependency, fill every column of its row (license, URL, scope, version, external audit, CI coverage,
commercial use, forced publication, notes). The audit search is **mandatory** here: every runtime dependency of this
package is cryptographic. Never write `No` without a search.

```bash
node scripts/check-licenses.mjs --update   # refresh specs/licenses.lock.json, review the diff
node scripts/check-licenses.mjs --fix      # refresh the "V. used" column
node scripts/check-licenses.mjs            # must pass (also runs in CI)
```

## Cryptography constraints

- No home-made primitive. Audited libraries only: libsodium (symmetric + X25519), ML-KEM-768 (FIPS 203) implementation.
- Any new or swapped crypto library needs explicit sign-off, a recorded audit status, and a new tag + `dist/` rebuild.
- After a release, update the `#vX.Y.Z` reference in `lexdocia-collect` (api, portail) and `piecemaster`, and their inventories.

## License policy

Same as `lexdocia-collect`: allowed permissive list; LGPL/MPL/CC-BY need a written justification in `licenses-policy.json`;
AGPL, GPL, SSPL, BUSL, Commons Clause, non-commercial, Elastic and proprietary are denied (CI fails).

## What CI enforces (`scripts/check-licenses.mjs`)

- Allowed license or reviewed exception for every package in `package-lock.json`.
- License drift against `licenses.lock.json` (relicensing / acquisition detection); unknown new package fails until reviewed.
- Every direct dependency has a row at the installed version.
- Weekly scheduled run (`security.yml`) catches changes without a commit.

## Review checklist for a dependency PR

- [ ] Row added/updated; URL and version checked
- [ ] `licenses.lock.json` diff read
- [ ] Audit status researched and linked
- [ ] Maintainer activity checked (last release, bus factor)
- [ ] `dist/` rebuilt and released if runtime dependencies changed
