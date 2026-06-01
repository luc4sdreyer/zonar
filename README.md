# zonar

A supply-chain auditor for the Zig package manager. It resolves your dependency
tree straight from the on-disk package cache, checks that every dependency is
pinned, and optionally re-verifies content hashes over the network.

> Requires **Zig 0.16**.

## Why

Three facts about Zig's package model shape this tool:

- **The hash is the identity.** A package doesn't come from a URL; it comes from
  a content hash. The URL is just one mirror that might serve bytes matching that
  hash. So the question "is this dependency pinned?" reduces to "does it have a
  hash, and is the hash the thing being trusted?"
- **The cache already has everything.** Once dependencies are fetched they live
  under the global cache at `<cache>/p/<hash>/`, each with its own
  `build.zig.zon`. The whole transitive tree can be resolved by reading files —
  no network required.
- **`build.zig` is code.** Every dependency's `build.zig` runs as unsandboxed
  code at configure time. Auditing what those scripts can do is the natural next
  step (see [Roadmap](#roadmap)).

zonar leans on Zig's own front-end to read manifests: it parses `build.zig.zon`
with the compiler's ZON parser (`std.zig.Ast` → `std.zig.ZonGen` → `Zoir`), the
same path `std.zon` uses internally.

## Install

```sh
git clone https://github.com/luc4sdreyer/zonar
cd zonar
zig build         # produces zig-out/bin/zonar
```

## Usage

```sh
# Audit the project in the current directory:
zonar audit

# Audit a specific manifest, as JSON:
zonar audit path/to/build.zig.zon --json

# Also re-fetch remote deps and verify their content hashes (needs network):
zonar audit --verify
```

Example against a project with a few problems:

```
zonar audit — demo 0.1.0
├─ pinned 1.0.0  ✔ pinned
│  └─ grandchild (url)  ⚠ unpinned
├─ unpinned (url)  ⚠ unpinned
├─ gitdep (git)  ⚠ mutable_ref
└─ local 9.9.9

Findings:
  [high] grandchild: declares a url but no hash; content is not pinned and whatever the url serves will be trusted
  [high] unpinned: declares a url but no hash; content is not pinned and whatever the url serves will be trusted
  [low] gitdep: git ref 'main' is not an immutable commit; content is pinned by hash, but the url provenance is mutable
  [info] gitdep: not present in the cache; run `zig build --fetch` to inspect it

Summary: 0 critical, 2 high, 1 low, 0 info
```

zonar exits non-zero when any finding is **high** severity or above, so it works
as a CI gate.

## What it checks

| Finding | Severity | Meaning |
| --- | --- | --- |
| `unpinned` | high | A `url`/`git` dependency with no `hash`. Content is not pinned. |
| `mutable_ref` | low | A git dependency whose committish isn't an immutable commit SHA. The hash still pins the content, but the URL provenance is mutable. |
| `not_in_cache` | info | The package isn't fetched yet, so it couldn't be inspected. |
| `hash_mismatch` | critical | `--verify` only: the re-fetched content's hash doesn't match the declared hash. |

A note on honesty: these are static signals about *what to review*, not verdicts.
A mutable git ref isn't malware; an unpinned URL isn't an attack. zonar points at
the weak spots and leaves the judgement to you.

## Options

| Flag | Effect |
| --- | --- |
| `--json` | Emit the audit as JSON (`{ root, findings, summary }`) instead of a tree. |
| `--verify` | Re-fetch remote dependencies with `zig fetch` and compare hashes. |
| `--cache <dir>` | Override the global cache directory (defaults to `ZIG_GLOBAL_CACHE_DIR`, then `zig env`). |
| `-h`, `--help` | Show help. |
| `-v`, `--version` | Show version. |

## Development

```sh
zig build test            # run all unit + integration tests
zig fmt --check build.zig src
```

The audit engine is also importable as a library module (`zonar`); the CLI is a
thin layer over it.

## Roadmap

Milestone 1 (this release) covers tree resolution and integrity checks. Planned:

- **`build.zig` capability scanner** — use `std.zig.Ast` to flag dependency build
  scripts that exec processes, touch the network, read the environment, or embed
  binary blobs.
- **SBOM export** in CycloneDX / SPDX.
- A native re-implementation of Zig's content hashing (today `--verify` shells
  out to `zig fetch`).

Explicit non-goals: runtime sandboxing (a job for Zig core) and a CVE/advisory
database (none exists to query for Zig yet).

## License

MIT — see [LICENSE](LICENSE).
