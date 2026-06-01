//! Resolves a project's transitive dependency tree by reading `build.zig.zon`
//! manifests off disk — no network required. A `hash` dependency is found at
//! `<cache>/p/<hash>/`; a `path` dependency is found relative to the directory
//! of the manifest that declares it. Already-visited packages are deduplicated
//! (and cycles broken) via a visited-set keyed by hash or resolved path.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const manifest = @import("manifest.zig");
const cache_mod = @import("cache.zig");

pub const Kind = enum { root, url, git, path };

pub const Status = enum {
    /// Manifest located and parsed.
    ok,
    /// Expected package directory / manifest was not present on disk.
    not_in_cache,
    /// Manifest was found but could not be parsed.
    parse_error,
    /// A `url` dependency with no `hash`: it cannot be located offline.
    unlocatable,
};

pub const Node = struct {
    name: []const u8,
    version: ?[]const u8 = null,
    kind: Kind,
    url: ?[]const u8 = null,
    hash: ?[]const u8 = null,
    path: ?[]const u8 = null,
    lazy: bool = false,
    status: Status = .ok,
    /// True if this package was already visited elsewhere in the tree; its
    /// children are elided to avoid repetition and cycles.
    duplicate: bool = false,
    children: []const Node = &.{},
};

pub const Tree = struct {
    root: Node,
};

pub const ResolveError = error{ RootUnreadable, OutOfMemory };

const Context = struct {
    arena: Allocator,
    io: Io,
    cache: cache_mod.Cache,
    /// Set of package identities already expanded (hash, or resolved path for
    /// path-deps). Maps to nothing; presence is what matters.
    visited: std.StringHashMapUnmanaged(void) = .empty,
};

/// Resolve the dependency tree rooted at `root_manifest_path` (a path to a
/// `build.zig.zon`). All allocations use `arena`.
pub fn resolve(
    arena: Allocator,
    io: Io,
    cache: cache_mod.Cache,
    root_manifest_path: []const u8,
) ResolveError!Tree {
    var ctx: Context = .{ .arena = arena, .io = io, .cache = cache };

    const source = readManifest(arena, io, root_manifest_path) catch return error.RootUnreadable;

    var diag: manifest.Diagnostics = .{};
    const m = manifest.parse(arena, source, &diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MalformedManifest => return error.RootUnreadable,
    };

    const base_dir = std.fs.path.dirname(root_manifest_path) orelse ".";
    var root: Node = .{
        .name = m.name orelse "(root)",
        .version = m.version,
        .kind = .root,
        .status = .ok,
    };
    root.children = try expandDeps(&ctx, m.dependencies, base_dir);
    return .{ .root = root };
}

fn expandDeps(ctx: *Context, deps: []const manifest.Dependency, base_dir: []const u8) ResolveError![]Node {
    const nodes = try ctx.arena.alloc(Node, deps.len);
    for (deps, 0..) |dep, i| {
        nodes[i] = try expandDep(ctx, dep, base_dir);
    }
    return nodes;
}

fn expandDep(ctx: *Context, dep: manifest.Dependency, base_dir: []const u8) ResolveError!Node {
    var node: Node = .{
        .name = dep.name,
        .kind = kindOf(dep),
        .url = dep.url,
        .hash = dep.hash,
        .path = dep.path,
        .lazy = dep.lazy,
    };

    // Determine where this dependency's own manifest lives, and the directory
    // its (path-based) children would be resolved against.
    var manifest_path: ?[]const u8 = null;
    var child_base: []const u8 = base_dir;
    var identity: ?[]const u8 = null;

    if (dep.hash) |hash| {
        const pkg_dir = try ctx.cache.packageDir(ctx.arena, hash);
        manifest_path = try std.fs.path.join(ctx.arena, &.{ pkg_dir, "build.zig.zon" });
        child_base = pkg_dir;
        identity = hash;
    } else if (dep.path) |rel| {
        const dir = try std.fs.path.resolve(ctx.arena, &.{ base_dir, rel });
        manifest_path = try std.fs.path.join(ctx.arena, &.{ dir, "build.zig.zon" });
        child_base = dir;
        identity = dir;
    } else {
        // A url with no hash, or a malformed entry: nothing to locate offline.
        node.status = .unlocatable;
        return node;
    }

    // Dedup / cycle guard.
    if (identity) |id| {
        if (ctx.visited.contains(id)) {
            node.duplicate = true;
            node.status = .ok;
            // Still try to fill in version cheaply if the manifest is present;
            // but skip re-expanding children.
            if (readManifest(ctx.arena, ctx.io, manifest_path.?)) |src| {
                if (manifest.parse(ctx.arena, src, null)) |m| {
                    node.version = m.version;
                } else |_| {}
            } else |_| {}
            return node;
        }
        try ctx.visited.put(ctx.arena, id, {});
    }

    const source = readManifest(ctx.arena, ctx.io, manifest_path.?) catch {
        node.status = .not_in_cache;
        return node;
    };

    const m = manifest.parse(ctx.arena, source, null) catch {
        node.status = .parse_error;
        return node;
    };

    node.version = m.version;
    node.status = .ok;
    node.children = try expandDeps(ctx, m.dependencies, child_base);
    return node;
}

fn kindOf(dep: manifest.Dependency) Kind {
    if (dep.url) |url| {
        if (std.mem.startsWith(u8, url, "git+")) return .git;
        return .url;
    }
    if (dep.path != null) return .path;
    return .url;
}

fn readManifest(arena: Allocator, io: Io, path: []const u8) ![:0]u8 {
    return std.Io.Dir.cwd().readFileAllocOptions(io, path, arena, .unlimited, .of(u8), 0);
}

const testing = std.testing;

test "kindOf classifies dependencies" {
    try testing.expectEqual(Kind.url, kindOf(.{ .name = "a", .url = "https://x/y.tar.gz" }));
    try testing.expectEqual(Kind.git, kindOf(.{ .name = "a", .url = "git+https://x/y.git#abc" }));
    try testing.expectEqual(Kind.path, kindOf(.{ .name = "a", .path = "../local" }));
}

test "resolve walks a transitive tree, dedups, and flags missing packages" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Lay out a fake cache + project under the tmp dir:
    //   cache/p/child-1.0.0-AAAA/build.zig.zon   (a leaf package)
    //   proj/build.zig.zon                        (root)
    // The root depends on `child` twice (a diamond, to exercise dedup) plus a
    // `missing` package whose hash is not present in the cache.
    const child_hash = "child-1.0.0-AAAAAAAAAAAA";
    {
        var d = try tmp.dir.createDirPathOpen(io, "cache/p/" ++ child_hash, .{});
        d.close(io);
    }
    {
        var d = try tmp.dir.createDirPathOpen(io, "proj", .{});
        d.close(io);
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "cache/p/" ++ child_hash ++ "/build.zig.zon",
        .data =
        \\.{ .name = .child, .version = "1.0.0", .dependencies = .{}, .paths = .{""} }
        ,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "proj/build.zig.zon",
        .data =
        \\.{
        \\    .name = .demo,
        \\    .version = "0.1.0",
        \\    .dependencies = .{
        \\        .first = .{ .url = "https://ex/c.tar.gz", .hash = "child-1.0.0-AAAAAAAAAAAA" },
        \\        .second = .{ .url = "https://ex/c.tar.gz", .hash = "child-1.0.0-AAAAAAAAAAAA" },
        \\        .missing = .{ .url = "https://ex/m.tar.gz", .hash = "missing-9.9.9-ZZZZZZZZZZZZ" },
        \\    },
        \\    .paths = .{""},
        \\}
        ,
    });

    const tmp_prefix = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path[0..]});
    const cache_root = try std.fmt.allocPrint(arena, "{s}/cache", .{tmp_prefix});
    const root_path = try std.fmt.allocPrint(arena, "{s}/proj/build.zig.zon", .{tmp_prefix});

    const tree = try resolve(arena, io, .{ .root = cache_root }, root_path);

    try testing.expectEqualStrings("demo", tree.root.name);
    try testing.expectEqual(@as(usize, 3), tree.root.children.len);

    const first = tree.root.children[0];
    try testing.expectEqualStrings("first", first.name);
    try testing.expectEqual(Status.ok, first.status);
    try testing.expectEqualStrings("1.0.0", first.version.?);
    try testing.expect(!first.duplicate);

    const second = tree.root.children[1];
    try testing.expect(second.duplicate); // same hash already expanded

    const missing = tree.root.children[2];
    try testing.expectEqual(Status.not_in_cache, missing.status);
}
