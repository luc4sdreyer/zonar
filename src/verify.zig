//! Opt-in content verification (`--verify`). For each dependency resolved from
//! the cache, recompute its content hash by running `zig fetch` on its on-disk
//! package directory (offline, no network), then compare against the hash the
//! package is filed under. A mismatch is critical: the cached content has been
//! modified and no longer matches its declared hash. This catches local cache
//! tampering or corruption without touching the network.
//!
//! `zig fetch` is the authoritative hasher, so the comparison is exact across
//! Zig versions. The cost is that it needs a `zig` on PATH and a `build.zig` in
//! the working directory (the tool quirk that `zig fetch` searches for one), so
//! we run it from the audited project's own directory. If `zig fetch` cannot
//! run, we degrade to an info finding rather than a false positive.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const resolver = @import("resolver.zig");
const integrity = @import("integrity.zig");
const Finding = integrity.Finding;

/// Recompute and verify every distinct cached dependency in `tree`, appending
/// findings to `out`. `project_dir` is the audited project's directory; it is
/// the working directory for `zig fetch` (which needs a `build.zig` nearby).
/// Only mismatches and recompute failures produce findings; clean packages are
/// silent.
pub fn verifyTree(
    arena: Allocator,
    io: Io,
    project_dir: []const u8,
    tree: resolver.Tree,
    out: *std.ArrayList(Finding),
) Allocator.Error!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    try verifyNode(arena, io, project_dir, tree.root, out, &seen);
}

fn verifyNode(
    arena: Allocator,
    io: Io,
    project_dir: []const u8,
    node: resolver.Node,
    out: *std.ArrayList(Finding),
    seen: *std.StringHashMapUnmanaged(void),
) Allocator.Error!void {
    if (shouldVerify(node)) {
        // The cache directory is a unique identity per hash; deduplicate on it
        // so a diamond dependency is only recomputed once.
        const dir = node.dir.?;
        if (!seen.contains(dir)) {
            try seen.put(arena, dir, {});
            if (try verifyOne(arena, io, project_dir, node.name, dir, node.hash.?)) |f| {
                try out.append(arena, f);
            }
        }
    }
    if (node.duplicate) return;
    for (node.children) |child| try verifyNode(arena, io, project_dir, child, out, seen);
}

/// A node is verifiable iff it was resolved from the cache under a modern hash:
/// the manifest parsed (`ok`), it carries a `hash` and an on-disk `dir`, and it
/// is a remote (url/git) dependency. Legacy `1220…` pins are skipped: a current
/// `zig fetch` computes the new format, so the hash would never match and the
/// staleness is already reported as `legacy_hash`.
pub fn shouldVerify(node: resolver.Node) bool {
    if (node.status != .ok) return false;
    if (node.kind != .url and node.kind != .git) return false;
    const hash = node.hash orelse return false;
    if (node.dir == null) return false;
    if (integrity.isLegacyMultihash(hash)) return false;
    return true;
}

/// Recompute the content hash of the package at `dir` and compare to `declared`.
/// Returns a critical finding on mismatch, an info finding when `zig fetch`
/// could not be run, or null when the recomputed hash matches.
pub fn verifyOne(
    arena: Allocator,
    io: Io,
    project_dir: []const u8,
    name: []const u8,
    dir: []const u8,
    declared: []const u8,
) Allocator.Error!?Finding {
    const result = std.process.run(arena, io, .{
        .argv = &.{ "zig", "fetch", dir },
        // `zig fetch` searches the cwd (and parents) for a build.zig; run it
        // from the audited project, which has one.
        .cwd = .{ .path = project_dir },
    }) catch {
        return Finding{
            .package = name,
            .severity = .info,
            .code = .hash_mismatch,
            .message = try std.fmt.allocPrint(arena, "could not run `zig fetch` to recompute the hash (is zig on PATH?)", .{}),
        };
    };

    const ok = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        return Finding{
            .package = name,
            .severity = .info,
            .code = .hash_mismatch,
            .message = try std.fmt.allocPrint(arena, "`zig fetch` failed; could not recompute the content hash (run zonar from the project directory)", .{}),
        };
    }

    const computed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (std.mem.eql(u8, computed, declared)) return null;

    return Finding{
        .package = name,
        .severity = .critical,
        .code = .hash_mismatch,
        .message = try std.fmt.allocPrint(
            arena,
            "cached content does not match its declared hash: filed under '{s}' but the package now hashes to '{s}' (the cached package has been modified)",
            .{ declared, computed },
        ),
    };
}

const testing = std.testing;

test "shouldVerify accepts a cached modern-hash remote dependency" {
    try testing.expect(shouldVerify(.{
        .name = "dep",
        .kind = .url,
        .url = "https://x/y.tar.gz",
        .hash = "dep-1.0.0-AAAA",
        .dir = "/cache/p/dep-1.0.0-AAAA",
        .status = .ok,
    }));
    try testing.expect(shouldVerify(.{
        .name = "dep",
        .kind = .git,
        .url = "git+https://x/r#abc",
        .hash = "dep-1.0.0-AAAA",
        .dir = "/cache/p/dep-1.0.0-AAAA",
        .status = .ok,
    }));
}

test "shouldVerify skips legacy, missing, path, root, and unlocated nodes" {
    // Legacy 1220 hash: zig fetch computes the new format, so it can't match.
    try testing.expect(!shouldVerify(.{
        .name = "dep",
        .kind = .url,
        .url = "https://x/y.tar.gz",
        .hash = "12206038da3a8d42de25babfadaa3b8fb01c223850a1f1ce309034172d150df61a8c",
        .dir = "/cache/p/x",
        .status = .ok,
    }));
    // Not in cache: nothing on disk to hash.
    try testing.expect(!shouldVerify(.{
        .name = "dep",
        .kind = .url,
        .hash = "dep-1.0.0-AAAA",
        .dir = "/cache/p/x",
        .status = .not_in_cache,
    }));
    // Path dependency: no declared hash to compare against.
    try testing.expect(!shouldVerify(.{
        .name = "dep",
        .kind = .path,
        .path = "../local",
        .dir = "/proj/local",
        .status = .ok,
    }));
    // Root has no hash.
    try testing.expect(!shouldVerify(.{ .name = "root", .kind = .root, .dir = "/proj", .status = .ok }));
    // A url with a hash but no resolved dir (cannot locate it offline).
    try testing.expect(!shouldVerify(.{
        .name = "dep",
        .kind = .url,
        .hash = "dep-1.0.0-AAAA",
        .dir = null,
        .status = .ok,
    }));
}
