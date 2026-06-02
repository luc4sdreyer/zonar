//! Resolves the Zig global package cache directory, where fetched packages live
//! under `<cache>/p/<hash>/`. The hash *is* the directory name.
//!
//! Resolution order (first hit wins):
//!   1. An explicit override (the `--cache` CLI flag).
//!   2. The `ZIG_GLOBAL_CACHE_DIR` environment variable.
//!   3. `zig env`, whose output is ZON we parse for `global_cache_dir`.
//!
//! We deliberately never hardcode the platform default path: the cache location
//! is overridable, and `zig env` is the authoritative source.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Cache = struct {
    /// The global cache root (the directory that contains `p/`).
    root: []const u8,

    /// Absolute path to a fetched package's directory: `<root>/p/<hash>`.
    pub fn packageDir(self: Cache, arena: Allocator, hash: []const u8) ![]u8 {
        return std.fs.path.join(arena, &.{ self.root, "p", hash });
    }
};

pub const ResolveError = error{
    /// `zig env` ran but its output could not be understood.
    ZigEnvUnparseable,
    /// `zig env` could not be executed (zig not on PATH, etc.).
    ZigEnvFailed,
    OutOfMemory,
};

/// Resolve the global cache. `override` short-circuits everything; it is the
/// value of the `--cache` flag (or null). `env` is the process environment
/// (`init.environ_map`), consulted for `ZIG_GLOBAL_CACHE_DIR`. Strings are
/// allocated with `arena`.
pub fn resolve(
    arena: Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    override: ?[]const u8,
) ResolveError!Cache {
    if (override) |dir| return .{ .root = try arena.dupe(u8, dir) };

    if (env.get("ZIG_GLOBAL_CACHE_DIR")) |dir| {
        if (dir.len != 0) return .{ .root = try arena.dupe(u8, dir) };
    }

    return resolveFromZigEnv(arena, io);
}

fn resolveFromZigEnv(arena: Allocator, io: Io) ResolveError!Cache {
    const result = std.process.run(arena, io, .{
        .argv = &.{ "zig", "env" },
    }) catch return error.ZigEnvFailed;

    switch (result.term) {
        .exited => |code| if (code != 0) return error.ZigEnvFailed,
        else => return error.ZigEnvFailed,
    }

    return .{ .root = try parseGlobalCacheDir(arena, result.stdout) };
}

/// Parse the `global_cache_dir` field out of `zig env` ZON output. Exposed
/// separately so it can be unit-tested without spawning a subprocess.
pub fn parseGlobalCacheDir(arena: Allocator, zig_env_output: []const u8) ResolveError![]const u8 {
    const source = arena.dupeZ(u8, zig_env_output) catch return error.OutOfMemory;
    const ZigEnv = struct { global_cache_dir: []const u8 };
    const parsed = std.zon.parse.fromSliceAlloc(
        ZigEnv,
        arena,
        source,
        null,
        .{ .ignore_unknown_fields = true },
    ) catch return error.ZigEnvUnparseable;
    return parsed.global_cache_dir;
}

const testing = std.testing;

test "parse global_cache_dir from zig env output" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const sample =
        \\.{
        \\    .zig_exe = "/opt/zig/zig",
        \\    .lib_dir = "/opt/zig/lib",
        \\    .global_cache_dir = "/home/u/.cache/zig",
        \\    .version = "0.16.0",
        \\    .env = .{ .HOME = "/home/u" },
        \\}
    ;
    const dir = try parseGlobalCacheDir(arena, sample);
    try testing.expectEqualStrings("/home/u/.cache/zig", dir);
}

test "packageDir joins cache root, p, and hash" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cache: Cache = .{ .root = "/home/u/.cache/zig" };
    const dir = try cache.packageDir(arena, "nasm-2.16.1-2-BWdcABvF_jM1");
    // packageDir joins with the native path separator, so build the expected
    // path the same way (this assertion runs on Windows too, where it's `\`).
    const sep = std.fs.path.sep_str;
    const expected = try std.mem.concat(arena, u8, &.{ "/home/u/.cache/zig", sep, "p", sep, "nasm-2.16.1-2-BWdcABvF_jM1" });
    try testing.expectEqualStrings(expected, dir);
}
