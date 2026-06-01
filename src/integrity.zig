//! Integrity heuristics over a resolved dependency tree. These are pure
//! functions: they inspect the declared `url`/`hash` of each node and emit
//! findings. They do not touch the network or the filesystem.
//!
//! A guiding principle (and the project's framing): in Zig the content `hash`
//! is the source of truth; the `url` is just a mirror. So a *mutable* git ref
//! is only a true integrity hole when there is no hash to pin the content —
//! otherwise it is a provenance smell, not a compromise. We grade accordingly,
//! and we describe findings as "review this," never "this is malware."

const std = @import("std");
const Allocator = std.mem.Allocator;
const resolver = @import("resolver.zig");

pub const Severity = enum {
    info,
    low,
    high,
    critical,

    pub fn label(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .low => "low",
            .high => "high",
            .critical => "critical",
        };
    }

    /// Rank for thresholding / sorting (higher is more severe).
    pub fn rank(self: Severity) u8 {
        return switch (self) {
            .info => 0,
            .low => 1,
            .high => 2,
            .critical => 3,
        };
    }
};

pub const Code = enum {
    /// A `url`/`git` dependency declared without a `hash`: content is unpinned.
    unpinned,
    /// A git dependency whose committish is not an immutable commit SHA.
    mutable_ref,
    /// The package was not found in the cache, so it could not be inspected.
    not_in_cache,
    /// `--verify`: the recomputed content hash did not match the declared hash.
    hash_mismatch,

    // Capability codes (emitted by the `--scan` build.zig scanner). These are a
    // report of what a build script *can do*, never a verdict; they are graded
    // below `high` so they never gate CI.
    /// The build script can execute external processes.
    cap_exec,
    /// The build script can access the network.
    cap_network,
    /// The build script reads environment variables.
    cap_env,
    /// The build script touches the filesystem outside the build graph.
    cap_filesystem,
    /// `--scan`: a build.zig was present but could not be parsed, so it was not
    /// scanned (not a capability — an inspection gap).
    unscannable,

    pub fn slug(self: Code) []const u8 {
        return @tagName(self);
    }
};

pub const Finding = struct {
    package: []const u8,
    severity: Severity,
    code: Code,
    message: []const u8,
    /// Optional source location, e.g. "build.zig:42", for findings tied to a
    /// specific line (the capability scanner sets this).
    location: ?[]const u8 = null,
};

/// Walk `tree` and append findings to `out`. Strings are allocated with `arena`.
pub fn check(arena: Allocator, tree: resolver.Tree, out: *std.ArrayList(Finding)) Allocator.Error!void {
    try checkNode(arena, tree.root, out);
}

fn checkNode(arena: Allocator, node: resolver.Node, out: *std.ArrayList(Finding)) Allocator.Error!void {
    try findingsFor(arena, node, out);
    if (node.duplicate) return;
    for (node.children) |child| try checkNode(arena, child, out);
}

/// Emit the findings for a single node. Exposed for unit testing.
pub fn findingsFor(arena: Allocator, node: resolver.Node, out: *std.ArrayList(Finding)) Allocator.Error!void {
    const has_remote = node.url != null and (node.kind == .url or node.kind == .git);

    if (has_remote and node.hash == null) {
        try out.append(arena, .{
            .package = node.name,
            .severity = .high,
            .code = .unpinned,
            .message = try std.fmt.allocPrint(
                arena,
                "declares a url but no hash; content is not pinned and whatever the url serves will be trusted",
                .{},
            ),
        });
    } else if (node.kind == .git and node.hash != null) {
        // Content is pinned by the hash, but a mutable committish is still a
        // provenance smell: clearing the hash would re-fetch non-deterministically.
        if (!isImmutableGitRef(node.url.?)) {
            try out.append(arena, .{
                .package = node.name,
                .severity = .low,
                .code = .mutable_ref,
                .message = try std.fmt.allocPrint(
                    arena,
                    "git ref '{s}' is not an immutable commit; content is pinned by hash, but the url provenance is mutable",
                    .{gitRef(node.url.?) orelse "(default branch)"},
                ),
            });
        }
    }

    if (node.status == .not_in_cache) {
        try out.append(arena, .{
            .package = node.name,
            .severity = .info,
            .code = .not_in_cache,
            .message = try std.fmt.allocPrint(
                arena,
                "not present in the cache; run `zig build --fetch` to inspect it",
                .{},
            ),
        });
    }
}

/// Extract the committish from a Zig git dependency url, i.e. the fragment after
/// `#` in `git+https://host/repo.git#<ref>`. Returns null if absent.
pub fn gitRef(url: []const u8) ?[]const u8 {
    const hash_idx = std.mem.lastIndexOfScalar(u8, url, '#') orelse return null;
    const ref = url[hash_idx + 1 ..];
    return if (ref.len == 0) null else ref;
}

/// A git ref is immutable iff it is a full 40-character hex commit SHA.
pub fn isImmutableGitRef(url: []const u8) bool {
    const ref = gitRef(url) orelse return false;
    if (ref.len != 40) return false;
    for (ref) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

const testing = std.testing;

test "gitRef extracts committish" {
    try testing.expectEqualStrings("main", gitRef("git+https://github.com/u/r.git#main").?);
    try testing.expectEqualStrings(
        "1234567890abcdef1234567890abcdef12345678",
        gitRef("git+https://github.com/u/r#1234567890abcdef1234567890abcdef12345678").?,
    );
    try testing.expect(gitRef("git+https://github.com/u/r") == null);
    try testing.expect(gitRef("git+https://github.com/u/r#") == null);
}

test "isImmutableGitRef recognizes commit SHAs only" {
    try testing.expect(isImmutableGitRef("git+https://x/r#1234567890abcdef1234567890abcdef12345678"));
    try testing.expect(!isImmutableGitRef("git+https://x/r#main"));
    try testing.expect(!isImmutableGitRef("git+https://x/r#v1.2.3"));
    try testing.expect(!isImmutableGitRef("git+https://x/r")); // no ref => mutable (HEAD)
    // 40 chars but not all hex:
    try testing.expect(!isImmutableGitRef("git+https://x/r#zzzz567890abcdef1234567890abcdef12345678"));
}

test "findingsFor flags unpinned url dependency" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{ .name = "dep", .kind = .url, .url = "https://x/y.tar.gz", .hash = null };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.unpinned, out.items[0].code);
    try testing.expectEqual(Severity.high, out.items[0].severity);
}

test "findingsFor flags mutable git ref as low when hash present" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .git,
        .url = "git+https://github.com/u/r.git#main",
        .hash = "r-1.0.0-AAAA",
    };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.mutable_ref, out.items[0].code);
    try testing.expectEqual(Severity.low, out.items[0].severity);
}

test "findingsFor is quiet for a properly pinned dependency" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .git,
        .url = "git+https://x/r#1234567890abcdef1234567890abcdef12345678",
        .hash = "r-1.0.0-AAAA",
    };
    try findingsFor(arena, node, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len);
}
