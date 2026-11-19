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
