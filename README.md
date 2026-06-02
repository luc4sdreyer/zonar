# zonar

[![CI](https://github.com/luc4sdreyer/zonar/actions/workflows/ci.yml/badge.svg)](https://github.com/luc4sdreyer/zonar/actions/workflows/ci.yml)

A supply-chain auditor for the Zig package manager. It resolves your dependency
tree straight from the on-disk package cache, checks that every dependency is
pinned, scans build scripts for risky capabilities, and exports an SBOM
(CycloneDX / SPDX).

> Building zonar requires **Zig 0.16**; the prebuilt binary audits projects on
> older Zig too (see [Compatibility](#compatibility)).

## Why

Three facts about Zig's package model shape this tool:

- The hash is the identity. A package doesn't come from a URL; it comes from
  a content hash. The URL is just one mirror that might serve bytes matching that
  hash. So the question "is this dependency pinned?" reduces to "does it have a
  hash, and is the hash the thing being trusted?"
- The cache already has everything. Once dependencies are fetched they live
  under the global cache at `<cache>/p/<hash>/`, each with its own
  `build.zig.zon`. The whole transitive tree can be resolved by reading files,
  with no network needed.
- `build.zig` is code. Every dependency's `build.zig` runs as unsandboxed
  code at configure time. Auditing what those scripts can do is the natural next
  step (see [Roadmap](#roadmap)).

zonar leans on Zig's own front-end to read manifests: it parses `build.zig.zon`
with the compiler's ZON parser (`std.zig.Ast` → `std.zig.ZonGen` → `Zoir`), the
same path `std.zon` uses internally.

## Install

### From a release

Releases ship signed binaries for Linux, macOS, and Windows. The install script
picks the right one for your platform, verifies its minisign signature, and
installs it (read it first; it tells you what it does):

```sh
curl -fsSL https://raw.githubusercontent.com/luc4sdreyer/zonar/main/tasks/install.sh | sh
```

On Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/luc4sdreyer/zonar/main/tasks/install.ps1 | iex
```

Prefer to do it by hand? Download the archive, its `.minisig`, and `minisign.pub`
from the [latest release](https://github.com/luc4sdreyer/zonar/releases/latest),
then verify before trusting the binary:

```sh
minisign -Vm zonar-x86_64-linux-musl.tar.gz -p minisign.pub
```

The public key is committed to this repo as `minisign.pub`.

### From source

```sh
git clone https://github.com/luc4sdreyer/zonar
cd zonar
zig build         # produces zig-out/bin/zonar
```

## Use as a library

The audit engine is exposed as a `zonar` module, so you can embed the resolver,
integrity checks, scanner, and SBOM export in your own `build.zig`. Add it as a
dependency by fetching the signed source tarball from a release:

```sh
zig fetch --save https://github.com/luc4sdreyer/zonar/releases/download/v0.2.0/zonar-v0.2.0.tar.gz
```

Then wire it into your `build.zig`:

```zig
const zonar = b.dependency("zonar", .{});
exe.root_module.addImport("zonar", zonar.module("zonar"));
```

`zig fetch --save` records the dependency by its content hash in your
`build.zig.zon`, which is immutable. Don't depend on `git+https://…#v0.2.0`
instead: a tag is a mutable ref that can be repointed, and zonar would flag it as
`mutable_ref` (the whole reason this tool exists).

## Compatibility

zonar audits a `build.zig.zon` statically: it reads the manifest (and, for
`--scan`/`--verify`, the on-disk package cache) without invoking the target
project's compiler. So the prebuilt `zonar` binary audits repositories built with
older Zig too. It is verified against 0.13.x and 0.14.x manifests and handles the
older shapes: a string `.name` (surfaced as `deprecated_name`), no `.fingerprint`,
and the pre-0.14 `1220…` hashes (surfaced as `legacy_hash`). For the
cache-dependent checks, point
`--cache` at the project's global cache (the `p/<hash>/` layout has been stable
since Zig 0.12).

Building zonar from source and using it as a library (`@import("zonar")`) require
Zig 0.16. On an older toolchain, download the standalone binary from a
[release](https://github.com/luc4sdreyer/zonar/releases) instead of depending on
the module.

## Usage

```sh
# Audit the project in the current directory:
zonar audit

# Audit a specific manifest, as JSON:
zonar audit path/to/build.zig.zon --json

# Also recompute each cached dependency's content hash and check it (offline):
zonar audit --verify
```

Example against a project with a few problems:

```
zonar audit: demo 0.1.0
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
zonar audit: demo 0.1.0
└─ evil 1.0.0  ✔ pinned

Findings:
  [low] evil (build.zig:3): process execution: b.addSystemCommand
  [low] evil (build.zig:5): network access: std.http
  [info] evil (build.zig:7): environment read: std.posix.getenv

Summary: 0 critical, 0 high, 2 low, 0 info
```

Capabilities are graded below `high` and
never affect the exit code: a build script using `addSystemCommand` is suspicious
to a human, but completely normal in many real projects. The scan is also
intentionally shallow. It matches qualified names in the AST and cannot follow
aliasing (`const p = std.process;`) or reflection, so treat it as "here is what to
review," never proof of anything.

### SBOM export (`--sbom`)

zonar can emit a Software Bill of Materials of the resolved dependency graph, in
`CycloneDX 1.6` or `SPDX 2.3` (JSON):

```sh
zonar audit --sbom=cyclonedx > sbom.cdx.json
zonar audit --sbom=spdx      > sbom.spdx.json
```

Notes specific to Zig:

- A package's identity is its content hash, so that hash is used directly as the
  CycloneDX `bom-ref`. It is *not* a standard SHA-256 digest, so it is carried as a
  `zonar:zig-hash` property (CycloneDX) or the package comment (SPDX) rather than
  masquerading in a `hashes`/`checksums` field.
- Zig has no registered PURL type, so components map to the closest resolvable
  identifier. A github-hosted dependency becomes `pkg:github/<owner>/<repo>@<ref>`
  (the `ref` is the pinned commit or tag, taken from the actual download URL, so a
  fork or mirror is reported as where the bytes really came from). Everything else
  falls back to `pkg:generic/<name>@<version>?download_url=...`.
- Any findings from the same run ride along. An `unpinned` dependency, for example,
  becomes a `zonar:finding:unpinned` property, so the SBOM flags its own weak spots.
- CycloneDX output is reproducible (no embedded timestamp or serial number), so it
  diffs cleanly in version control. SPDX requires a unique document namespace and a
  creation timestamp, so SPDX output is not byte-reproducible.

The audit still runs in SBOM mode, so `--fail-on` (below) applies to the exit code.
You can generate an SBOM and gate CI in one command.

## What it checks

| Finding | Severity | Meaning |
| --- | --- | --- |
| `unpinned` | high | A `url`/`git` dependency with no `hash`. Content is not pinned. |
| `mutable_ref` | low | A git dependency whose committish isn't an immutable commit SHA. The hash still pins the content, but the URL provenance is mutable. |
| `legacy_hash` | info | A `hash` in the pre-0.14 `1220…` multihash format. Content is pinned, but a current Zig computes a different hash format, so the pin won't match a freshly-fetched package. |
| `deprecated_name` | info | The package's manifest declares `.name` as a string (the pre-0.14 form). A current Zig requires an enum literal and won't parse the manifest. |
| `not_in_cache` | info | The package isn't fetched yet, so it couldn't be inspected. |
| `hash_mismatch` | critical | `--verify` only: a cached package's recomputed content hash doesn't match the hash it's filed under (the cached content has been modified). |
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
| `--verify` | Recompute each cached dependency's content hash with `zig fetch` and check it against the hash it's filed under (offline; needs `zig` and a `build.zig` in the project). |
| `--cache <dir>` | Override the global cache directory (defaults to `ZIG_GLOBAL_CACHE_DIR`, then `zig env`). |
| `--fail-on=<level>` | Exit non-zero at this severity or above: `info`, `low`, `high` (default), `critical`, or `never`. |
| `-h`, `--help` | Show help. |
| `-v`, `--version` | Show version. |

## Development

```sh
zig build test            # run all unit tests
zig fmt --check build.zig src
zig build docs            # API docs into zig-out/docs
./tasks/integration-test.sh   # audit real-world manifests vs. golden output
```

`tasks/integration-test.sh` audits a corpus of real `build.zig.zon` manifests
(mach, ghostty, capy, zap) under `testdata/integration/`, pinned to upstream
commits, and diffs zonar's JSON against committed goldens. It runs offline, so it
works in CI. Regenerate the corpus from the pinned commits with
`tasks/refresh-integration-fixtures.sh`.

The audit engine is also importable as a library module (`zonar`); the CLI is a
thin layer over it. API documentation is published at
<https://luc4sdreyer.github.io/zonar/>. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the full dev loop, linting, and how releases are cut and verified.

## Roadmap

Done: tree resolution, integrity checks, the `--scan` `build.zig` capability scanner,
and `--sbom` export (CycloneDX / SPDX) with `--fail-on` CI gating. Planned:

- More capabilities for `--scan`: `@embedFile` blobs, `@cImport`, absolute-path
  string literals, and following simple aliasing.
- A native re-implementation of Zig's content hashing (today `--verify` shells
  out to `zig fetch`).

Explicit non-goals: runtime sandboxing (a job for Zig core) and a CVE/advisory
database (none exists to query for Zig yet).

## License

MIT. See [LICENSE](LICENSE).
