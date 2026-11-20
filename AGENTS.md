# Agent rules — cloudflare-tool

These project rules extend `~/.config/opencode/AGENTS.md`. If anything here
conflicts with the global rules, the global rules win.

## Releases

Releases are built and published only by the `Release` GitHub Actions workflow
(`.github/workflows/release.yml`). Never publish artifacts or create GitHub
Releases by hand.

### Versioning

- **Semantic Versioning** (`MAJOR.MINOR.PATCH`). The crate version lives in the
  workspace manifest `Cargo.toml` under `[workspace.package].version`; each
  member crate inherits it with `version.workspace = true`. There is exactly one
  version for the whole workspace — never set a member's version independently.
- **Tags** are `v` + the manifest version, e.g. `v0.1.0`.
- **Pre-releases** use `-alpha.N`, `-beta.N`, or `-rc.N` (N starts at 1 and
  increments), e.g. `v0.1.0-beta.1`. The workflow marks any suffixed tag as a
  GitHub pre-release and does not promote it to "latest".
- The first release of a version is `-beta.1`, not a bare `vX.Y.Z`. Only promote
  to a stable `vX.Y.Z` tag after a beta/rc has been validated.

### Cutting a release

1. Update `[workspace.package].version` in `Cargo.toml` to the exact target
   version without the `v` (e.g. `0.1.0-beta.1`). The lockfile updates on the
   normal build; commit `Cargo.lock` with the change.
2. Regenerate `cargo check --workspace --all-targets --all-features --locked`
   and confirm it passes. Confirm CI on `main` is green.
3. Commit version changes to `main` and push. **Do not tag until CI is green on
   that exact commit.**
4. Create an annotated tag on that commit and push it:

   ```sh
   git tag -a v0.1.0-beta.1 -m "cftool v0.1.0-beta.1"
   git push origin v0.1.0-beta.1
   ```

5. The `verify` job rejects a tag whose name disagrees with the manifest version
   or uses an unsupported suffix — fix the version or the tag, never bypass this.
6. Monitor the `Release` workflow to completion. It builds Linux x86_64, Windows
   x86_64, and macOS arm64 archives with `cftool` + `cftool-gui`, publishes
   `SHA256SUMS`, generates release notes, and sets the pre-release flag.

### Release rules

- Never reuse or move a tag. If a release is broken, cut the next `N` (e.g.
  `v0.1.0-beta.2`); do not force-push the old tag.
- Never release with `--locked` disabled; reproducible builds from `Cargo.lock`
  are required.
- Keep `contents: read` as the workflow default; only the `publish` job may
  elevate to `contents: write`.
- Never commit credentials, tokens, or secrets. Releases use `GITHUB_TOKEN`.
- Manual re-runs use the `workflow_dispatch` input `tag` and must name an
  existing valid tag; the same version checks apply.
- Verify a downloaded archive with `sha256sum -c SHA256SUMS` (or `Get-FileHash`
  on Windows) before trusting it.

## Publishing to crates.io

crates.io publishing is **opt-in and separate** from GitHub releases. It is done
only by the `crates` job in `.github/workflows/release.yml`, never by hand from a
developer machine for a release (use `cargo login` locally only for manual,
out-of-band publishes).

### Authentication

- Never commit a token, put one in a command line, or paste one into chat.
- **CI**: repository secret `CARGO_REGISTRY_TOKEN`. The workflow passes it to
  `cargo publish` via environment variable; it is masked in logs.
- **Local (optional)**: `cargo login` stores a token in
  `~/.cargo/credentials.toml` (Windows: `%USERPROFILE%\.cargo\credentials.toml`).
  `cargo logout` removes it. This file is outside the repo and must never be
  added to it.
- To revoke a leaked token, delete it at https://crates.io/settings/tokens
  immediately.

### Enabling the publish job

The `crates` job is gated by the repository variable `PUBLISH_TO_CRATES_IO`.
It does nothing until that variable is the string `true`:

```sh
gh variable set PUBLISH_TO_CRATES_IO --repo mahyartdb/cloudflare-tool --body true
```

Set it only when you intend the next tag to publish. Leave it unset/`false`
otherwise. The job may be safely re-run: it skips versions already on crates.io.

### Manifest requirements (already in place — keep them)

- The workspace version is the single source of truth in
  `[workspace.package].version`; members inherit it with `version.workspace = true`.
- Every internal dependency is declared in `[workspace.dependencies]` with both
  `version` (matching the workspace version) and `path`; members use
  `{ workspace = true }`. Cargo publish requires a version requirement on every
  path dependency — removing it breaks publishing.
- Every crate inherits `description` and `repository` from the workspace;
  crates.io requires these.

### Publish order and rules

- The `crates` job publishes in dependency order:
  `cftool-core` → `cftool-warp` → `cftool-cdn` → `cftool` → `cftool-gui`,
  retrying until each new version is indexed before publishing its dependents.
- A publish is permanent: a version can never be overwritten or deleted. Fix a
  broken release with a new version (bump `N`, e.g. `-beta.2`), never a repush.
- `cargo yank --version X.Y.Z` hides a broken version from new dependency
  resolution but does not delete code.
- Local verification before a real publish: `cargo publish --dry-run -p <crate>`.
  Note that crates with internal dependencies cannot pass a full dry run until
  those dependencies exist on crates.io; that is expected and not a failure of
  the local manifest.
