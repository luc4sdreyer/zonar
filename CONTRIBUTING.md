# Contributing to zonar

Thanks for your interest. zonar targets **Zig 0.16** and has no external
dependencies (a supply-chain auditor shouldn't add attack surface), so the setup
is just a Zig toolchain.

## Development loop

```sh
zig build                    # build the CLI (zig-out/bin/zonar)
zig build test               # run all unit tests
zig fmt --check build.zig src
zig build docs               # build the API docs into zig-out/docs
./tasks/integration-test.sh  # audit real-world manifests vs. golden output
```

CI runs the formatter, the test suite on Linux/macOS/Windows, a docs build,
[zlint](https://github.com/DonIsaac/zlint) (blocking), SBOM schema validation,
and the integration test. To run zlint locally, download the binary for your
platform from its releases page and run `zlint` from the repo root.

The integration test (`tasks/integration-test.sh`) audits real `build.zig.zon`
manifests under `testdata/integration/` against committed golden JSON, offline.
When a bundled manifest changes upstream, regenerate the corpus from the pinned
commits with `tasks/refresh-integration-fixtures.sh` (needs network) and commit
the result.

Editor support: install [ZLS](https://github.com/zigtools/zls), the Zig Language
Server, for completion and inline diagnostics.

## Pull requests

- Keep the working tree formatted (`zig fmt`) and the tests green.
- Match the surrounding style; prefer the standard library over new dependencies.
- One logical change per PR.

## Releases (maintainers)

Checklist for cutting `vX.Y.Z`:

1. Bump `.version` in `build.zig.zon` to `X.Y.Z` (the single source of truth; the
   tag must match it, and `zonar --version` is derived from it).
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under a new `[X.Y.Z]` heading.
3. Open a PR, get green CI, and merge.
4. Tag the merge commit and push:
   ```sh
   git tag -a vX.Y.Z -m "zonar X.Y.Z"
   git push origin vX.Y.Z
   ```
5. Confirm the release assets appear and the signature verifies (below).

`.github/workflows/release.yml` cross-compiles every target from a single Linux
runner (passing `-Dversion` from the tag), signs each archive plus the
`zig fetch` source tarball with [minisign](https://jedisct1.github.io/minisign/),
and publishes a GitHub release with the archives, the source tarball, their
`.minisig` signatures, a `SHA256SUMS` file, and the public key.

### Signing key setup (one time)

```sh
minisign -G -W -p minisign.pub -s minisign.key   # -W: no password, for CI
```

Commit `minisign.pub` to the repo root, put its fingerprint in the README, and
add the **contents** of `minisign.key` as the `MINISIGN_SECRET_KEY` repository
secret (Settings → Secrets and variables → Actions). Keep `minisign.key` off the
repo and out of your shell history.

### Verifying a release

```sh
minisign -Vm zonar-x86_64-linux-musl.tar.gz -p minisign.pub
```
