//! zonar — a supply-chain auditor for the Zig package manager.
//!
//! In Zig, the content hash is the identity of a package; the url is just one
//! possible mirror; and every dependency's `build.zig` runs as unsandboxed code
//! at configure time. zonar leans into that model: it resolves the transitive
//! dependency tree straight from the on-disk package cache (no network), verifies
//! that dependencies are pinned, and reports what it finds.
//!
//! This is the library surface; the `zonar` binary (src/main.zig) is a thin CLI
//! over these modules.

const std = @import("std");

pub const cache = @import("cache.zig");
pub const manifest = @import("manifest.zig");
pub const resolver = @import("resolver.zig");
pub const integrity = @import("integrity.zig");
pub const verify = @import("verify.zig");
pub const report = @import("report.zig");

// Commonly used types, re-exported for convenience.
pub const Cache = cache.Cache;
pub const Manifest = manifest.Manifest;
pub const Dependency = manifest.Dependency;
pub const Tree = resolver.Tree;
pub const Node = resolver.Node;
pub const Finding = integrity.Finding;
pub const Severity = integrity.Severity;

test {
    // Pull every module's tests into the library test binary.
    _ = cache;
    _ = manifest;
    _ = resolver;
    _ = integrity;
    _ = verify;
    _ = report;
}
