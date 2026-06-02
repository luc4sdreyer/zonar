//! Integrity heuristics over a resolved dependency tree. These are pure
//! functions: they inspect the declared `url`/`hash` of each node and emit
//! findings. They do not touch the network or the filesystem.
//!
//! A guiding principle (and the project's framing): in Zig the content `hash`
//! is the source of truth; the `url` is just a mirror. So a *mutable* git ref
//! is only a true integrity hole when there is no hash to pin the content.
//! Otherwise it is a provenance smell, not a compromise. We grade accordingly,
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
    /// A `hash` in the pre-0.14 sha2-256 multihash format (`1220…`). Content is
    /// still pinned, but a current Zig computes a different hash format, so the
    /// pin will not match a freshly-fetched package.
    legacy_hash,
    /// The package's manifest declares `.name` as a string literal (the pre-0.14
    /// form). A current Zig requires an enum literal and will not parse it.
    deprecated_name,
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
    /// scanned (not a capability, an inspection gap).
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

    // Independent of how the content is fetched (url or git), a legacy-format
    // hash is a provenance smell: still content-pinned, but a current Zig can
    // no longer reproduce it.
    if (node.hash) |hash| {
        if (isLegacyMultihash(hash)) {
            try out.append(arena, .{
                .package = node.name,
                .severity = .info,
                .code = .legacy_hash,
                .message = try std.fmt.allocPrint(
                    arena,
                    "pinned with a legacy pre-0.14 hash; content is pinned but a current Zig computes a different hash format",
                    .{},
                ),
            });
        }
    }

    // A string `.name` is a pre-0.14 manifest shape. The content may be fine,
    // but a current Zig cannot parse the manifest, so the package is stale and
    // cannot be re-fetched without an edit. zonar parses it leniently anyway.
    if (node.name_is_legacy_string) {
        try out.append(arena, .{
            .package = node.name,
            .severity = .info,
            .code = .deprecated_name,
            .message = try std.fmt.allocPrint(
                arena,
                "manifest declares `.name` as a string (pre-0.14 form); a current Zig requires an enum literal and will not parse this manifest",
                .{},
            ),
        });
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

/// True iff `hash` is a pre-0.14 sha2-256 multihash: exactly 68 lowercase hex
/// digits prefixed `1220` (`0x12` = sha2-256, `0x20` = 32-byte digest length).
/// The current format is `name-version-<base64>` or `N-V-__…`, neither of which
/// matches, so this cleanly distinguishes legacy pins.
pub fn isLegacyMultihash(hash: []const u8) bool {
    if (hash.len != 68) return false;
    if (!std.mem.startsWith(u8, hash, "1220")) return false;
    for (hash) |c| {
        const lower_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!lower_hex) return false;
    }
    return true;
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

test "isLegacyMultihash recognizes pre-0.14 hashes only" {
    // 68 lowercase hex chars beginning with 1220 (real capy macos_sdk pin).
    try testing.expect(isLegacyMultihash("12209cc9ee372456eda52b71cf9ae77dcc707fa42c9f9d68996b5bf7495b53229c2e"));
    // Modern name-version-digest form.
    try testing.expect(!isLegacyMultihash("zigimg-0.1.0-8_eo2nWlEgCddu8EGLOM_RkYshx3sC8tWv-yYA4-htS6"));
    // Modern name-less form.
    try testing.expect(!isLegacyMultihash("N-V-__8AAG0-dAOcye43JFbtpStxz5rnfcxwf6Qsn51omWtb"));
    // Right prefix, wrong length.
    try testing.expect(!isLegacyMultihash("1220abcd"));
    // Uppercase hex is not the canonical legacy form.
    try testing.expect(!isLegacyMultihash("1220" ++ "A" ** 64));
    // 68 chars but not all hex.
    try testing.expect(!isLegacyMultihash("1220" ++ "z" ** 64));
}

test "findingsFor flags legacy multihash as info" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .url,
        .url = "https://x/y.tar.gz",
        .hash = "12206038da3a8d42de25babfadaa3b8fb01c223850a1f1ce309034172d150df61a8c",
    };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.legacy_hash, out.items[0].code);
    try testing.expectEqual(Severity.info, out.items[0].severity);
}

test "findingsFor emits both legacy_hash and not_in_cache when applicable" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .url,
        .url = "https://x/y.tar.gz",
        .hash = "12206038da3a8d42de25babfadaa3b8fb01c223850a1f1ce309034172d150df61a8c",
        .status = .not_in_cache,
    };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(Code.legacy_hash, out.items[0].code);
    try testing.expectEqual(Code.not_in_cache, out.items[1].code);
}

test "findingsFor flags a string-named manifest as deprecated_name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .git,
        .url = "git+https://x/r#1234567890abcdef1234567890abcdef12345678",
        .hash = "r-1.0.0-AAAA",
        .name_is_legacy_string = true,
    };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.deprecated_name, out.items[0].code);
    try testing.expectEqual(Severity.info, out.items[0].severity);
}

test "findingsFor emits deprecated_name after legacy_hash" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A pre-0.14 dependency typically has both a string name and a legacy hash.
    // Ordering is fixed (legacy_hash then deprecated_name) so JSON goldens are
    // deterministic.
    var out: std.ArrayList(Finding) = .empty;
    const node: resolver.Node = .{
        .name = "dep",
        .kind = .url,
        .url = "https://x/y.tar.gz",
        .hash = "12206038da3a8d42de25babfadaa3b8fb01c223850a1f1ce309034172d150df61a8c",
        .name_is_legacy_string = true,
    };
    try findingsFor(arena, node, &out);

    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(Code.legacy_hash, out.items[0].code);
    try testing.expectEqual(Code.deprecated_name, out.items[1].code);
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
