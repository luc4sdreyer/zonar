# zonar

A supply-chain auditor for the Zig package manager. It resolves your dependency
tree straight from the on-disk package cache, checks that every dependency is
pinned, scans build scripts for risky capabilities, and exports an SBOM
(CycloneDX / SPDX).

> Requires **Zig 0.16**.

## Why

Three facts about Zig's package model shape this tool:

- **The hash is the identity.** A package doesn't come from a URL; it comes from
  a content hash. The URL is just one mirror that might serve bytes matching that
  hash. So the question "is this dependency pinned?" reduces to "does it have a
  hash, and is the hash the thing being trusted?"
- **The cache already has everything.** Once dependencies are fetched they live
  under the global cache at `<cache>/p/<hash>/`, each with its own
  `build.zig.zon`. The whole transitive tree can be resolved by reading files,
  with no network needed.
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

### Scanning build scripts (`--scan`)

Every dependency's `build.zig` runs as unsandboxed code at configure time. With
`--scan`, zonar parses each one with the compiler's own AST (`std.zig.Ast`) and
reports what the script can do at configure time, such as running processes,
opening network connections, or reading the environment and filesystem:

```
zonar audit --scan — demo 0.1.0
└─ evil 1.0.0  ✔ pinned

Findings:
  [low] evil (build.zig:3): process execution: b.addSystemCommand
  [low] evil (build.zig:5): network access: std.http
  [info] evil (build.zig:7): environment read: std.posix.getenv

Summary: 0 critical, 0 high, 2 low, 0 info
```

Capabilities are a **report, not a verdict**. They are graded below `high` and
never affect the exit code: a build script using `addSystemCommand` is suspicious
to a human, but completely normal in many real projects. The scan is also
intentionally shallow. It matches qualified names in the AST and cannot follow
aliasing (`const p = std.process;`) or reflection, so treat it as "here is what to
review," never proof of anything.

### SBOM export (`--sbom`)

zonar can emit a Software Bill of Materials of the resolved dependency graph, in
**CycloneDX 1.6** or **SPDX 2.3** (JSON):

```sh
zonar audit --sbom=cyclonedx > sbom.cdx.json
zonar audit --sbom=spdx      > sbom.spdx.json
```

Notes specific to Zig:

- A package's identity is its **content hash**, so that hash is used directly as the
  CycloneDX `bom-ref`. It is *not* a standard SHA-256 digest, so it is carried as a
  `zonar:zig-hash` property (CycloneDX) or the package comment (SPDX) rather than
  masquerading in a `hashes`/`checksums` field.
- Components use a `pkg:generic/<name>@<version>?download_url=...` package URL, since
  Zig has no registered PURL type.
- Any findings from the same run ride along. An `unpinned` dependency, for example,
  becomes a `zonar:finding:unpinned` property, so the SBOM flags its own weak spots.
- **CycloneDX output is reproducible** (no embedded timestamp or serial number), so it
  diffs cleanly in version control. SPDX requires a unique document namespace and a
  creation timestamp, so SPDX output is not byte-reproducible.

The audit still runs in SBOM mode, so `--fail-on` (below) applies to the exit code.
You can generate an SBOM and gate CI in one command.

## What it checks

| Finding | Severity | Meaning |
| --- | --- | --- |
| `unpinned` | high | A `url`/`git` dependency with no `hash`. Content is not pinned. |
| `mutable_ref` | low | A git dependency whose committish isn't an immutable commit SHA. The hash still pins the content, but the URL provenance is mutable. |
| `not_in_cache` | info | The package isn't fetched yet, so it couldn't be inspected. |
| `hash_mismatch` | critical | `--verify` only: the re-fetched content's hash doesn't match the declared hash. |
| `cap_exec` | low | `--scan` only: the build script can execute external processes. |
| `cap_network` | low | `--scan` only: the build script can access the network. |
| `cap_env` | info | `--scan` only: the build script reads environment variables. |
| `cap_filesystem` | info | `--scan` only: the build script touches the filesystem outside the build graph. |
| `unscannable` | info | `--scan` only: a dependency's `build.zig` couldn't be parsed, so it wasn't scanned. |

A note on honesty: these are static signals about *what to review*, not verdicts.
A mutable git ref isn't malware; an unpinned URL isn't an attack. zonar points at
the weak spots and leaves the judgement to you.

## Options

| Flag | Effect |
| --- | --- |
| `--json` | Emit the audit as JSON (`{ root, findings, summary }`) instead of a tree. |
| `--sbom=<format>` | Emit an SBOM instead of a report. `format` is `cyclonedx` or `spdx`. |
| `--scan` | Scan each dependency's `build.zig` for risky capabilities (exec, network, env, fs). |
| `--verify` | Re-fetch remote dependencies with `zig fetch` and compare hashes. |
| `--cache <dir>` | Override the global cache directory (defaults to `ZIG_GLOBAL_CACHE_DIR`, then `zig env`). |
| `--fail-on=<level>` | Exit non-zero at this severity or above: `info`, `low`, `high` (default), `critical`, or `never`. |
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

Done: tree resolution, integrity checks, the `--scan` `build.zig` capability scanner,
and `--sbom` export (CycloneDX / SPDX) with `--fail-on` CI gating. Planned:

- **More capabilities** for `--scan`: `@embedFile` blobs, `@cImport`, absolute-path
  string literals, and following simple aliasing.
- A native re-implementation of Zig's content hashing (today `--verify` shells
  out to `zig fetch`).

Explicit non-goals: runtime sandboxing (a job for Zig core) and a CVE/advisory
database (none exists to query for Zig yet).

## License

MIT. See [LICENSE](LICENSE).
