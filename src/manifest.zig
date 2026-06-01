//! Parses a `build.zig.zon` manifest into a structured form.
//!
//! The `.dependencies` table is keyed by arbitrary dependency names, so it
//! cannot be modelled with a static type for `std.zon.parse`. Instead we drive
//! the compiler's own ZON front-end directly: `Ast.parse(.zon)` ->
//! `ZonGen.generate` -> a dynamic `Zoir` tree we walk by hand. This is exactly
//! how `std.zon.parse` works internally; we just need the dynamic shape.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Zoir = std.zig.Zoir;

pub const Dependency = struct {
    name: []const u8,
    url: ?[]const u8 = null,
    hash: ?[]const u8 = null,
    path: ?[]const u8 = null,
    lazy: bool = false,
};

pub const Manifest = struct {
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    minimum_zig_version: ?[]const u8 = null,
    dependencies: []const Dependency = &.{},
};

pub const Diagnostics = struct {
    /// A human-readable explanation, allocated in the caller's allocator, set
    /// when `parse` returns `error.MalformedManifest`.
    message: ?[]const u8 = null,
};

pub const ParseError = error{ MalformedManifest, OutOfMemory };

/// Parse `source` (which must be NUL-terminated, as ZON requires) into a
/// `Manifest`. All returned strings are allocated with `arena`; free by
/// freeing the arena.
pub fn parse(arena: Allocator, source: [:0]const u8, diag: ?*Diagnostics) ParseError!Manifest {
    var ast = try std.zig.Ast.parse(arena, source, .zon);
    defer ast.deinit(arena);

    var zoir = try std.zig.ZonGen.generate(arena, ast, .{});
    defer zoir.deinit(arena);

    if (zoir.hasCompileErrors()) {
        if (diag) |d| {
            const first = zoir.compile_errors[0];
            d.message = try arena.dupe(u8, first.msg.get(zoir));
        }
        return error.MalformedManifest;
    }

    const root = Zoir.Node.Index.root.get(zoir);

    var manifest: Manifest = .{};
    manifest.name = try dupeEnumOrString(arena, zoir, field(zoir, root, "name"));
    manifest.version = try dupeString(arena, field(zoir, root, "version"));
    manifest.minimum_zig_version = try dupeString(arena, field(zoir, root, "minimum_zig_version"));

    if (field(zoir, root, "dependencies")) |deps_node| {
        manifest.dependencies = try parseDependencies(arena, zoir, deps_node);
    }

    return manifest;
}

fn parseDependencies(arena: Allocator, zoir: Zoir, node: Zoir.Node) ParseError![]const Dependency {
    const sl = switch (node) {
        .struct_literal => |sl| sl,
        // `.dependencies = .{}` parses as an empty struct/array literal.
        .empty_literal => return &.{},
        else => return error.MalformedManifest,
    };

    const deps = try arena.alloc(Dependency, sl.names.len);
    for (sl.names, 0..) |name_nts, i| {
        const value = sl.vals.at(@intCast(i)).get(zoir);
        deps[i] = .{
            .name = try arena.dupe(u8, name_nts.get(zoir)),
            .url = try dupeString(arena, field(zoir, value, "url")),
            .hash = try dupeString(arena, field(zoir, value, "hash")),
            .path = try dupeString(arena, field(zoir, value, "path")),
            .lazy = boolField(zoir, value, "lazy") orelse false,
        };
    }
    return deps;
}

/// Look up a named field of a struct-literal node, returning its value node.
fn field(zoir: Zoir, node: Zoir.Node, name: []const u8) ?Zoir.Node {
    const sl = switch (node) {
        .struct_literal => |sl| sl,
        else => return null,
    };
    for (sl.names, 0..) |nts, i| {
        if (std.mem.eql(u8, nts.get(zoir), name)) return sl.vals.at(@intCast(i)).get(zoir);
    }
    return null;
}

fn dupeString(arena: Allocator, node: ?Zoir.Node) ParseError!?[]const u8 {
    const n = node orelse return null;
    return switch (n) {
        .string_literal => |s| try arena.dupe(u8, s),
        else => null,
    };
}

fn dupeEnumOrString(arena: Allocator, zoir: Zoir, node: ?Zoir.Node) ParseError!?[]const u8 {
    const n = node orelse return null;
    return switch (n) {
        // `name` is an enum literal (e.g. `.zonar`) in the current format.
        .enum_literal => |e| try arena.dupe(u8, e.get(zoir)),
        .string_literal => |s| try arena.dupe(u8, s),
        else => null,
    };
}

fn boolField(zoir: Zoir, node: Zoir.Node, name: []const u8) ?bool {
    const n = field(zoir, node, name) orelse return null;
    return switch (n) {
        .true => true,
        .false => false,
        else => null,
    };
}

const testing = std.testing;

test "parse manifest with mixed dependencies" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const src =
        \\.{
        \\    .name = .myproj,
        \\    .version = "1.2.3",
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{
        \\        .pinned = .{ .url = "https://example.com/a.tar.gz", .hash = "a-1.0.0-AAAA" },
        \\        .unpinned = .{ .url = "https://example.com/b.tar.gz" },
        \\        .local = .{ .path = "../local" },
        \\        .lazydep = .{ .url = "https://example.com/c.tar.gz", .hash = "c-1.0.0-CCCC", .lazy = true },
        \\    },
        \\    .paths = .{""},
        \\}
    ;

    const m = try parse(arena, src, null);
    try testing.expectEqualStrings("myproj", m.name.?);
    try testing.expectEqualStrings("1.2.3", m.version.?);
    try testing.expectEqualStrings("0.16.0", m.minimum_zig_version.?);
    try testing.expectEqual(@as(usize, 4), m.dependencies.len);

    const pinned = m.dependencies[0];
    try testing.expectEqualStrings("pinned", pinned.name);
    try testing.expectEqualStrings("https://example.com/a.tar.gz", pinned.url.?);
    try testing.expectEqualStrings("a-1.0.0-AAAA", pinned.hash.?);
    try testing.expect(pinned.path == null);
    try testing.expect(!pinned.lazy);

    const unpinned = m.dependencies[1];
    try testing.expectEqualStrings("unpinned", unpinned.name);
    try testing.expect(unpinned.url != null);
    try testing.expect(unpinned.hash == null);

    const local = m.dependencies[2];
    try testing.expectEqualStrings("../local", local.path.?);
    try testing.expect(local.url == null);

    try testing.expect(m.dependencies[3].lazy);
}

test "parse manifest with empty dependencies" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const m = try parse(arena, ".{ .name = .x, .version = \"0.0.0\", .dependencies = .{} }", null);
    try testing.expectEqual(@as(usize, 0), m.dependencies.len);
}

test "malformed manifest reports a diagnostic" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var diag: Diagnostics = .{};
    const result = parse(arena, ".{ .name = , }", &diag);
    try testing.expectError(error.MalformedManifest, result);
    try testing.expect(diag.message != null);
}
