# Integration corpus

Real `build.zig.zon` manifests from public Zig projects, pinned to upstream
commits, used by [`tasks/integration-test.sh`](../../tasks/integration-test.sh)
to audit zonar against real-world input. The test is **offline**: it runs the
built `zonar` binary against each fixture and diffs its `--json` output against
the committed `expected.json` golden. It runs in CI.

## Layout

Each `<repo>/` directory holds:

- `build.zig.zon` — the upstream root manifest, byte-for-byte.
- `SOURCE` — the upstream repo and the exact commit the files were taken from.
- `cache/p/<hash>/` and/or `pkg/<name>/` — vendored dependency packages, holding
  only the two files zonar reads: `build.zig` and `build.zig.zon`. Present only
  for the few deps we want *resolved* (rather than reported `not_in_cache`), so
  resolution and `--scan` run against real content.
- `expected.json` — zonar's exact compact `--json` output (the golden).

## What each fixture exercises

- **mach** — breadth: many modern-pinned `url` deps, no vendored cache, so every
  dependency reports `not_in_cache`. Stresses the resolver on a large tree.
- **ghostty** — `path` deps (`.path = "./pkg/..."`). `wuffs` is vendored as a
  clean C shim (resolves, scans clean, exposes its own transitive deps);
  `gtk4-layer-shell` is vendored to exercise `--scan` — its build script runs
  `wayland-scanner` via `addSystemCommand`, so the audit reports `cap_exec`.
- **capy** — a `git+https#<commit>` dep (`zigimg`, vendored, resolves clean with
  no `mutable_ref` because the committish is an immutable SHA) alongside two deps
  pinned with legacy `1220…` hashes, which surface `legacy_hash`.
- **zap** — a zero-dependency control: the audit must stay completely clean.

## A note on the vendored `build.zig` files

These are **third-party build scripts committed verbatim as test fixtures**.
zonar only ever parses them as an AST to report what they *can do*; it never
executes them. They carry no capability beyond what their upstream authors
wrote, and nothing here runs them.

## Regenerating

When a bundled manifest changes upstream, bump the pinned commit in
[`tasks/refresh-integration-fixtures.sh`](../../tasks/refresh-integration-fixtures.sh)
and run it (needs network) to refetch the manifests, re-vendor the deps, and
regenerate the goldens. Then review and commit the diff.
