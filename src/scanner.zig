//! The `--scan` capability scanner. For each resolved dependency that is present
//! in the cache, it parses the package's `build.zig` with the compiler's own AST
//! (`std.zig.Ast`) and reports what the build script is *capable of*: executing
//! processes, accessing the network, reading the environment or filesystem.
//!
//! Build scripts run as unsandboxed code at configure time, so this is the
//! question that matters most. But the analysis is deliberately humble: it walks
//! `field_access` nodes and matches their source text against a table of known
//! qualified names. It does NOT do semantic analysis, so aliasing
//! (`const p = std.process;`) or reflection can hide a capability. Findings are
//! therefore graded below `high` (they never gate CI) and are phrased as
//! "here is what to review," never "this is malware."

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Ast = std.zig.Ast;

const resolver = @import("resolver.zig");
const integrity = @import("integrity.zig");
const Finding = integrity.Finding;
const Severity = integrity.Severity;
const Code = integrity.Code;

const Pattern = struct {
    /// A qualified substring to look for in a `field_access` node's source.
    needle: []const u8,
    code: Code,
    severity: Severity,
    /// Short human label for the capability, shown in the finding message.
    label: []const u8,
};

/// Capability table. Needles are qualified on purpose (`process.Child`, not bare
/// `process`) so an unrelated `std.process` namespace reference doesn't trip a
/// finding. All severities are below `high`, so capabilities never gate CI.
const table = [_]Pattern{
    // Process execution.
    .{ .needle = "addSystemCommand", .code = .cap_exec, .severity = .low, .label = "process execution" },
    .{ .needle = "process.Child", .code = .cap_exec, .severity = .low, .label = "process execution" },
    .{ .needle = "process.run", .code = .cap_exec, .severity = .low, .label = "process execution" },
    .{ .needle = "process.spawn", .code = .cap_exec, .severity = .low, .label = "process execution" },
    .{ .needle = "posix.exec", .code = .cap_exec, .severity = .low, .label = "process execution" },
    // Network access.
    .{ .needle = "std.http", .code = .cap_network, .severity = .low, .label = "network access" },
    .{ .needle = "std.net", .code = .cap_network, .severity = .low, .label = "network access" },
    .{ .needle = "posix.socket", .code = .cap_network, .severity = .low, .label = "network access" },
    // Environment reads.
    .{ .needle = "posix.getenv", .code = .cap_env, .severity = .info, .label = "environment read" },
    .{ .needle = "process.getEnvVarOwned", .code = .cap_env, .severity = .info, .label = "environment read" },
    .{ .needle = "process.getEnvMap", .code = .cap_env, .severity = .info, .label = "environment read" },
    // Filesystem access outside the build graph.
    .{ .needle = "fs.cwd", .code = .cap_filesystem, .severity = .info, .label = "filesystem access" },
    .{ .needle = "openFileAbsolute", .code = .cap_filesystem, .severity = .info, .label = "filesystem access" },
    .{ .needle = "openDirAbsolute", .code = .cap_filesystem, .severity = .info, .label = "filesystem access" },
    .{ .needle = "realpathAlloc", .code = .cap_filesystem, .severity = .info, .label = "filesystem access" },
};

/// Scan every cached *dependency* in `tree`, appending capability findings to
/// `out`. The first-party root package is intentionally skipped: `--scan` audits
/// third-party build scripts, not your own. Packages are scanned once each
/// (deduped by directory); duplicates and packages not present on disk are skipped.
pub fn scanTree(
    arena: Allocator,
    io: Io,
    tree: resolver.Tree,
    out: *std.ArrayList(Finding),
) Allocator.Error!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (tree.root.children) |child| try scanNode(arena, io, child, out, &seen);
}

fn scanNode(
    arena: Allocator,
    io: Io,
    node: resolver.Node,
    out: *std.ArrayList(Finding),
    seen: *std.StringHashMapUnmanaged(void),
) Allocator.Error!void {
    if (node.status == .ok) {
        if (node.dir) |dir| {
            if (!seen.contains(dir)) {
                try seen.put(arena, dir, {});
                try scanPackage(arena, io, node.name, dir, out);
            }
        }
    }
    if (node.duplicate) return;
    for (node.children) |child| try scanNode(arena, io, child, out, seen);
}

fn scanPackage(
    arena: Allocator,
    io: Io,
    package: []const u8,
    dir: []const u8,
    out: *std.ArrayList(Finding),
) Allocator.Error!void {
    const path = try std.fs.path.join(arena, &.{ dir, "build.zig" });
    const source = readSource(arena, io, path) catch |err| switch (err) {
        // Out of memory must not be masked as a clean scan: propagate it so the
        // audit fails loudly rather than silently omitting a dependency.
        error.OutOfMemory => return error.OutOfMemory,
        // No build.zig (some packages are data-only) or otherwise unreadable:
        // nothing to scan here.
        else => return,
    };
    try scanSource(arena, package, source, out);
}

/// Append a capability finding, deduplicated per `(code, line)` so repeated hits
/// on one line collapse to a single finding. `message` is the prebuilt detail.
fn appendCap(
    arena: Allocator,
    package: []const u8,
    out: *std.ArrayList(Finding),
    seen: *std.StringHashMapUnmanaged(void),
    code: Code,
    severity: Severity,
    message: []const u8,
    line: usize,
) Allocator.Error!void {
    const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{ code.slug(), line });
    if (seen.contains(key)) return;
    try seen.put(arena, key, {});
    try out.append(arena, .{
        .package = package,
        .severity = severity,
        .code = code,
        .message = message,
        .location = try std.fmt.allocPrint(arena, "build.zig:{d}", .{line}),
    });
}

/// If `raw` (a quoted string-literal token, quotes included) looks like an
/// absolute filesystem path, return the inner path; otherwise null. The
/// heuristic is a leading `/` (POSIX) or an `X:\` / `X:/` drive prefix
/// (Windows). A relative path, a URL (`https://...`), or a format string does
/// not match because none of them start that way.
fn absolutePathLiteral(raw: []const u8) ?[]const u8 {
    if (raw.len < 3) return null;
    if (raw[0] != '"' or raw[raw.len - 1] != '"') return null;
    const inner = raw[1 .. raw.len - 1];
    if (inner.len == 0) return null;
    if (inner[0] == '/') return inner;
    if (inner.len >= 3 and std.ascii.isAlphabetic(inner[0]) and inner[1] == ':' and
        (inner[2] == '\\' or inner[2] == '/')) return inner;
    return null;
}

/// Parse `source` as a `build.zig` and append capability findings. Pure (no IO),
/// so it is the unit-testable core. Findings are deduplicated per `(code, line)`.
pub fn scanSource(
    arena: Allocator,
    package: []const u8,
    source: [:0]const u8,
    out: *std.ArrayList(Finding),
) Allocator.Error!void {
    var ast = try Ast.parse(arena, source, .zig);
    defer ast.deinit(arena);

    if (ast.errors.len != 0) {
        try out.append(arena, .{
            .package = package,
            .severity = .info,
            .code = .unscannable,
            .message = try std.fmt.allocPrint(arena, "build.zig could not be parsed; not scanned", .{}),
        });
        return;
    }

    var seen: std.StringHashMapUnmanaged(void) = .empty;

    // Pass 1: qualified field accesses against the needle table (process,
    // network, environment, filesystem).
    var i: u32 = 0;
    while (i < ast.nodes.len) : (i += 1) {
        const idx: Ast.Node.Index = @enumFromInt(i);
        if (ast.nodeTag(idx) != .field_access) continue;

        const src = ast.getNodeSource(idx);
        for (table) |p| {
            if (std.mem.indexOf(u8, src, p.needle) == null) continue;
            const line = ast.tokenLocation(0, ast.firstToken(idx)).line + 1;
            const msg = try std.fmt.allocPrint(arena, "{s}: {s}", .{ p.label, std.mem.trim(u8, src, " \t\r\n") });
            try appendCap(arena, package, out, &seen, p.code, p.severity, msg, line);
        }
    }

    // Pass 2: builtins (`@cImport`, `@embedFile`) and absolute-path string
    // literals. These are token-level, not qualified field accesses.
    var t: u32 = 0;
    while (t < ast.tokens.len) : (t += 1) {
        switch (ast.tokenTag(t)) {
            .builtin => {
                const name = ast.tokenSlice(t);
                if (std.mem.eql(u8, name, "@cImport")) {
                    const line = ast.tokenLocation(0, t).line + 1;
                    try appendCap(arena, package, out, &seen, .cap_cimport, .low, "C interop: @cImport", line);
                } else if (std.mem.eql(u8, name, "@embedFile")) {
                    const line = ast.tokenLocation(0, t).line + 1;
                    try appendCap(arena, package, out, &seen, .cap_embed, .info, "embedded file: @embedFile", line);
                }
            },
            .string_literal => {
                if (absolutePathLiteral(ast.tokenSlice(t))) |p| {
                    const line = ast.tokenLocation(0, t).line + 1;
                    const msg = try std.fmt.allocPrint(arena, "absolute path: {s}", .{p});
                    try appendCap(arena, package, out, &seen, .cap_filesystem, .info, msg, line);
                }
            },
            else => {},
        }
    }
}

fn readSource(arena: Allocator, io: Io, path: []const u8) ![:0]u8 {
    return std.Io.Dir.cwd().readFileAllocOptions(io, path, arena, .unlimited, .of(u8), 0);
}

const testing = std.testing;

fn codesFor(arena: Allocator, source: [:0]const u8) ![]Code {
    var out: std.ArrayList(Finding) = .empty;
    try scanSource(arena, "test", source, &out);
    const codes = try arena.alloc(Code, out.items.len);
    for (out.items, 0..) |f, i| codes[i] = f.code;
    return codes;
}

fn hasCode(codes: []const Code, code: Code) bool {
    for (codes) |c| {
        if (c == code) return true;
    }
    return false;
}

test "benign build.zig yields no capability findings" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    const exe = b.addExecutable(.{ .name = "x" });
        \\    b.installArtifact(exe);
        \\}
    ;
    const codes = try codesFor(arena, src);
    try testing.expectEqual(@as(usize, 0), codes.len);
}

test "detects process execution" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    const run = b.addSystemCommand(&.{"curl"});
        \\    _ = run;
        \\}
    ;
    try scanSource(arena, "evil", src, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.cap_exec, out.items[0].code);
    try testing.expectEqual(Severity.low, out.items[0].severity);
    try testing.expectEqualStrings("build.zig:3", out.items[0].location.?);
}

test "detects network and process.Child" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    var c: std.http.Client = undefined;
        \\    _ = &c;
        \\    const child = std.process.Child.init(&.{"sh"}, b.allocator);
        \\    _ = child;
        \\}
    ;
    const codes = try codesFor(arena, src);
    try testing.expect(hasCode(codes, .cap_network));
    try testing.expect(hasCode(codes, .cap_exec));
}

test "detects env and filesystem" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    _ = b;
        \\    const home = std.posix.getenv("HOME");
        \\    _ = home;
        \\    const cwd = std.fs.cwd();
        \\    _ = cwd;
        \\}
    ;
    const codes = try codesFor(arena, src);
    try testing.expect(hasCode(codes, .cap_env));
    try testing.expect(hasCode(codes, .cap_filesystem));
}

test "detects @cImport and @embedFile builtins" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    _ = b;
        \\    const c = @cImport(@cInclude("stdio.h"));
        \\    _ = c;
        \\    const blob = @embedFile("payload.bin");
        \\    _ = blob;
        \\}
    ;
    try scanSource(arena, "p", src, &out);

    var cimport: ?Finding = null;
    var embed: ?Finding = null;
    for (out.items) |f| {
        if (f.code == .cap_cimport) cimport = f;
        if (f.code == .cap_embed) embed = f;
    }
    try testing.expect(cimport != null);
    try testing.expectEqual(Severity.low, cimport.?.severity);
    try testing.expectEqualStrings("build.zig:4", cimport.?.location.?);
    try testing.expect(embed != null);
    try testing.expectEqual(Severity.info, embed.?.severity);
    try testing.expectEqualStrings("build.zig:6", embed.?.location.?);
    // @import / @cInclude must not be mistaken for a flagged builtin.
    try testing.expectEqual(@as(usize, 2), out.items.len);
}

test "flags absolute-path string literals but not relative paths or urls" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    b.addIncludePath(.{ .cwd_relative = "/usr/include" });
        \\    b.addIncludePath(.{ .cwd_relative = "vendor/include" });
        \\    const url = "https://example.com/x.tar.gz";
        \\    _ = url;
        \\}
    ;
    try scanSource(arena, "p", src, &out);

    // Only the "/usr/include" literal trips cap_filesystem; the relative path
    // and the URL do not.
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.cap_filesystem, out.items[0].code);
    try testing.expectEqual(Severity.info, out.items[0].severity);
    try testing.expectEqualStrings("build.zig:3", out.items[0].location.?);
}

test "absolutePathLiteral heuristic" {
    try testing.expectEqualStrings("/etc/passwd", absolutePathLiteral("\"/etc/passwd\"").?);
    try testing.expectEqualStrings("C:\\Windows", absolutePathLiteral("\"C:\\Windows\"").?);
    try testing.expectEqualStrings("D:/data", absolutePathLiteral("\"D:/data\"").?);
    try testing.expect(absolutePathLiteral("\"./relative\"") == null);
    try testing.expect(absolutePathLiteral("\"vendor/include\"") == null);
    try testing.expect(absolutePathLiteral("\"https://example.com\"") == null);
    try testing.expect(absolutePathLiteral("\"\"") == null);
}

test "nested field access on one line yields a single finding" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    // std.process.Child.init contains both "std.process.Child" and the longer
    // ".init" node, both matching "process.Child" on the same line.
    const src =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    const c = std.process.Child.init(&.{"sh"}, b.allocator);
        \\    _ = c;
        \\}
    ;
    try scanSource(arena, "p", src, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
}

test "unparseable build.zig degrades gracefully" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(Finding) = .empty;
    try scanSource(arena, "broken", "pub fn build(b: *std.Build) void { this is not zig", &out);
    // One info note coded as unscannable (not a capability), no crash.
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Severity.info, out.items[0].severity);
    try testing.expectEqual(Code.unscannable, out.items[0].code);
}

test "scanTree reads and scans a cached package's build.zig" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const hash = "evil-1.0.0-AAAAAAAAAAAA";
    {
        var d = try tmp.dir.createDirPathOpen(io, "cache/p/" ++ hash, .{});
        d.close(io);
    }
    {
        var d = try tmp.dir.createDirPathOpen(io, "proj", .{});
        d.close(io);
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "cache/p/" ++ hash ++ "/build.zig.zon",
        .data = ".{ .name = .evil, .version = \"1.0.0\", .dependencies = .{}, .paths = .{\"\"} }",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "cache/p/" ++ hash ++ "/build.zig",
        .data =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    _ = b.addSystemCommand(&.{"curl"});
        \\}
        ,
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "proj/build.zig.zon",
        .data =
        \\.{
        \\    .name = .demo,
        \\    .version = "0.1.0",
        \\    .dependencies = .{
        \\        .evil = .{ .url = "https://x/e.tar.gz", .hash = "evil-1.0.0-AAAAAAAAAAAA" },
        \\    },
        \\    .paths = .{""},
        \\}
        ,
    });
    // The root's own build.zig also uses a capability, but it must NOT be reported,
    // because --scan audits dependencies, not first-party code.
    try tmp.dir.writeFile(io, .{
        .sub_path = "proj/build.zig",
        .data =
        \\const std = @import("std");
        \\pub fn build(b: *std.Build) void {
        \\    _ = b.addSystemCommand(&.{"make"});
        \\}
        ,
    });

    const tmp_prefix = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path[0..]});
    const cache_root = try std.fmt.allocPrint(arena, "{s}/cache", .{tmp_prefix});
    const root_path = try std.fmt.allocPrint(arena, "{s}/proj/build.zig.zon", .{tmp_prefix});

    const tree = try resolver.resolve(arena, io, .{ .root = cache_root }, root_path);
    var out: std.ArrayList(Finding) = .empty;
    try scanTree(arena, io, tree, &out);

    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Code.cap_exec, out.items[0].code);
    try testing.expectEqualStrings("evil", out.items[0].package);
    try testing.expectEqualStrings("build.zig:3", out.items[0].location.?);
}
