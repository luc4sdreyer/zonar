//! Opt-in content verification (`--verify`). For each remote dependency with a
//! declared hash, shell out to `zig fetch <url>` (which fetches the content,
//! recomputes its hash, and prints it), then compare against the declared hash.
//! A mismatch is critical: the url is serving something other than what the
//! manifest claims. This is the one part of the audit that requires network.
//!
//! v0.1 delegates hashing to `zig fetch` rather than reimplementing Zig's exact
//! content-addressing; a native implementation is future work.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const resolver = @import("resolver.zig");
const integrity = @import("integrity.zig");
const Finding = integrity.Finding;

/// Verify every distinct (url, hash) remote dependency in `tree`, appending
/// findings to `out`. Only mismatches and verification failures produce
/// findings; successful matches are silent.
pub fn verifyTree(
    arena: Allocator,
    io: Io,
    tree: resolver.Tree,
    out: *std.ArrayList(Finding),
) Allocator.Error!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    try verifyNode(arena, io, tree.root, out, &seen);
}

fn verifyNode(
    arena: Allocator,
    io: Io,
    node: resolver.Node,
    out: *std.ArrayList(Finding),
    seen: *std.StringHashMapUnmanaged(void),
) Allocator.Error!void {
    if (node.url) |url| {
        if (node.hash) |declared| {
            // Deduplicate by the (url, hash) pair, not by hash alone: two deps
            // can declare the same hash from different urls, and we must fetch
            // each url to catch a mirror serving different bytes under that hash.
            const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ url, declared });
            if (!seen.contains(key)) {
                try seen.put(arena, key, {});
                if (try verifyOne(arena, io, node.name, url, declared)) |f| {
                    try out.append(arena, f);
                }
            }
        }
    }
    if (node.duplicate) return;
    for (node.children) |child| try verifyNode(arena, io, child, out, seen);
}

/// Verify a single dependency. Returns a finding on mismatch or on failure to
/// run `zig fetch`; returns null when the recomputed hash matches.
pub fn verifyOne(
    arena: Allocator,
    io: Io,
    name: []const u8,
    url: []const u8,
    declared: []const u8,
) Allocator.Error!?Finding {
    const result = std.process.run(arena, io, .{
        .argv = &.{ "zig", "fetch", url },
    }) catch {
        return Finding{
            .package = name,
            .severity = .info,
            .code = .hash_mismatch,
            .message = try std.fmt.allocPrint(arena, "could not run `zig fetch` to verify (network or toolchain error)", .{}),
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
            .message = try std.fmt.allocPrint(arena, "`zig fetch` failed; could not verify content hash", .{}),
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
            "content hash mismatch: manifest declares '{s}' but the url serves '{s}'",
            .{ declared, computed },
        ),
    };
}
