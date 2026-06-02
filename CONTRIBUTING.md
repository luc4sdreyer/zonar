# Contributing to zonar

Thanks for your interest. zonar targets **Zig 0.16** and has no external
dependencies (a supply-chain auditor shouldn't add attack surface), so the setup
is just a Zig toolchain.

## Development loop

```sh
zig build            # build the CLI (zig-out/bin/zonar)
zig build test       # run all unit + integration tests
zig fmt --check build.zig src
zig build docs       # build the API docs into zig-out/docs
```

CI runs the formatter, the test suite on Linux/macOS/Windows, a docs build, and
[zlint](https://github.com/DonIsaac/zlint). To run zlint locally, download the
binary for your platform from its releases page and run `zlint` from the repo
root. The lint job is currently non-blocking; please keep it clean anyway.

Editor support: install [ZLS](https://github.com/zigtools/zls), the Zig Language
Server, for completion and inline diagnostics.

## Pull requests

- Keep the working tree formatted (`zig fmt`) and the tests green.
- Match the surrounding style; prefer the standard library over new dependencies.
- One logical change per PR.

## Releases (maintainers)

Releases are cut by pushing a tag:

```sh
git tag v0.2.0
git push origin v0.2.0
```

`.github/workflows/release.yml` cross-compiles every target from a single Linux
runner, signs each archive with [minisign](https://jedisct1.github.io/minisign/),
and publishes a GitHub release with the archives, their `.minisig` signatures, a
`SHA256SUMS` file, and the public key.

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
