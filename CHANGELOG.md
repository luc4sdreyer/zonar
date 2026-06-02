# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-06-02

### Added
- `legacy_hash` finding (info): flags a dependency pinned with a pre-0.14
  sha2-256 multihash (`1220…`). The content is still pinned, but a current Zig
  computes a different hash format, so the pin will not match a freshly-fetched
  package — a provenance/staleness signal.
- Integration corpus under `testdata/integration/`: real `build.zig.zon`
  manifests from mach, ghostty, capy, and zap (pinned to upstream commits),
  audited offline against committed golden JSON by `tasks/integration-test.sh`
  (now a CI job). It exercises legacy-hash pins, a `git+commit` dep, path deps,
  and a real `--scan` capability (ghostty's `gtk4-layer-shell` runs
  `wayland-scanner` → `cap_exec`). `tasks/refresh-integration-fixtures.sh`
  regenerates the fixtures from the pinned commits.

### Changed
- CI: the shipped shell scripts under `tasks/` are now shellcheck-linted.

## [0.2.0] - 2026-06-02

### Added
- Library consumption: a signed source tarball is attached to each release, so
  projects can `zig fetch --save` zonar and `@import("zonar")` the audit engine.
  See the "Use as a library" section in the README.
- `zonar --version` is injected at build time from `build.zig.zon` (or `-Dversion`
  at release time), so it always matches the released tag.
- This changelog.

### Changed
- CI: the zlint job is now required (no longer `continue-on-error`).
- CI: added an SBOM schema-validation job that validates zonar's own CycloneDX and
  SPDX output against the official schemas.

## [0.1.0] - 2026-06-02

### Added
- Dependency tree resolver that reads `build.zig.zon` manifests from the on-disk
  package cache (no network), with transitive resolution, dedup, and cycle guard.
- Integrity checks: `unpinned`, `mutable_ref`, `not_in_cache`, and `hash_mismatch`
  (the last via the opt-in `--verify`, which re-fetches with `zig fetch`).
- `--scan`: a `build.zig` capability scanner built on `std.zig.Ast` that flags
  process execution, network, and environment/filesystem access.
- `--sbom=cyclonedx|spdx`: Software Bill of Materials export.
- `--fail-on=<level>`: configurable exit-code threshold for CI gating.
- Text tree and JSON output; importable library module.
- Signed cross-platform release binaries (minisign) and GitHub Pages API docs.

[Unreleased]: https://github.com/luc4sdreyer/zonar/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/luc4sdreyer/zonar/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/luc4sdreyer/zonar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/luc4sdreyer/zonar/releases/tag/v0.1.0
