//! Findings baseline: accept a reviewed set of findings so CI fails only on
//! *new* ones ("review once, gate on new"). A finding's baseline identity is
//! `(package, code, message)`, deliberately excluding the source line, so an
//! accepted finding survives the line shifts that come with reformatting a
//! dependency. The baseline file is JSON, sorted for clean diffs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

const integrity = @import("integrity.zig");
const json = @import("json.zig");
const Finding = integrity.Finding;

pub const format_version = 1;

pub const Error = error{MalformedBaseline} || Allocator.Error;

/// The stable identity of a finding for baselining: package, code, and message
/// joined with NULs. The source line is excluded on purpose.
fn fingerprint(arena: Allocator, package: []const u8, code: []const u8, message: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "{s}\x00{s}\x00{s}", .{ package, code, message });
}

pub const Baseline = struct {
    /// fingerprint -> whether it matched a finding this run (for stale detection)
    entries: std.StringHashMapUnmanaged(bool) = .empty,

    /// Parse a baseline file's JSON `source`. Unknown fields are tolerated; a
    /// syntactically invalid file is `error.MalformedBaseline`.
    pub fn load(arena: Allocator, source: []const u8) Error!Baseline {
        const File = struct {
            version: u32 = format_version,
            findings: []const Entry = &.{},
            const Entry = struct { code: []const u8, package: []const u8, message: []const u8 };
        };
        const parsed = std.json.parseFromSliceLeaky(File, arena, source, .{
            .ignore_unknown_fields = true,
        }) catch return error.MalformedBaseline;

        var b: Baseline = .{};
        for (parsed.findings) |e| {
            try b.entries.put(arena, try fingerprint(arena, e.package, e.code, e.message), false);
        }
        return b;
    }

    /// Return the findings NOT present in the baseline (the new ones), marking
    /// matched entries so `staleCount` can report the unused ones.
    pub fn suppress(self: *Baseline, arena: Allocator, findings: []const Finding) Allocator.Error![]const Finding {
        var kept: std.ArrayListUnmanaged(Finding) = .empty;
        for (findings) |f| {
            const fp = try fingerprint(arena, f.package, f.code.slug(), f.message);
            if (self.entries.getPtr(fp)) |matched| {
                matched.* = true;
            } else {
                try kept.append(arena, f);
            }
        }
        return kept.items;
    }

    /// Count baseline entries that matched no finding this run. They are stale
    /// (the underlying finding was fixed or changed) and can be pruned with
    /// `--update-baseline`.
    pub fn staleCount(self: *const Baseline) usize {
        var n: usize = 0;
        var it = self.entries.valueIterator();
        while (it.next()) |matched| {
            if (!matched.*) n += 1;
        }
        return n;
    }
};

/// Serialize `findings` as a baseline JSON document, sorted by (code, package,
/// message) and de-duplicated, so it diffs cleanly. The source line is omitted.
pub fn serialize(arena: Allocator, out: *Writer, findings: []const Finding) !void {
    const sorted = try arena.dupe(Finding, findings);
    std.sort.block(Finding, sorted, {}, lessThan);

    try out.print("{{\"version\":{d},\"findings\":[", .{format_version});
    var last: ?Finding = null;
    var first = true;
    for (sorted) |f| {
        if (last) |p| {
            if (sameIdentity(p, f)) continue; // collapse same identity on different lines
        }
        last = f;
        if (!first) try out.writeAll(",");
        first = false;
        try out.writeAll("{\"code\":");
        try json.writeString(out, f.code.slug());
        try out.writeAll(",\"package\":");
        try json.writeString(out, f.package);
        try out.writeAll(",\"message\":");
        try json.writeString(out, f.message);
        try out.writeAll("}");
    }
    try out.writeAll("]}\n");
}

fn sameIdentity(a: Finding, b: Finding) bool {
    return a.code == b.code and
        std.mem.eql(u8, a.package, b.package) and
        std.mem.eql(u8, a.message, b.message);
}

fn lessThan(_: void, a: Finding, b: Finding) bool {
    switch (std.mem.order(u8, a.code.slug(), b.code.slug())) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (std.mem.order(u8, a.package, b.package)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    return std.mem.order(u8, a.message, b.message) == .lt;
}

const testing = std.testing;

fn sampleFindings() []const Finding {
    return &.{
        .{ .package = "wuffs", .severity = .low, .code = .cap_exec, .message = "process execution: addSystemCommand", .location = "build.zig:3" },
        .{ .package = "depa", .severity = .high, .code = .unpinned, .message = "declares a url but no hash" },
        // Same identity as the first, different line: must collapse in the file.
        .{ .package = "wuffs", .severity = .low, .code = .cap_exec, .message = "process execution: addSystemCommand", .location = "build.zig:9" },
    };
}

test "serialize is sorted, de-duplicated, and line-free" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try serialize(arena, &aw.writer, sampleFindings());

    // Parse it back: two distinct entries (the duplicate cap_exec collapsed),
    // sorted with cap_exec before unpinned, and no "location" field.
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expectEqual(@as(i64, format_version), root.get("version").?.integer);
    const items = root.get("findings").?.array.items;
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("cap_exec", items[0].object.get("code").?.string);
    try testing.expectEqualStrings("wuffs", items[0].object.get("package").?.string);
    try testing.expect(items[0].object.get("location") == null);
    try testing.expectEqualStrings("unpinned", items[1].object.get("code").?.string);
}

test "load and suppress keep only new findings, ignoring line numbers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Baseline accepts the cap_exec finding (recorded at a different line).
    var aw: Writer.Allocating = .init(arena);
    try serialize(arena, &aw.writer, &.{
        .{ .package = "wuffs", .severity = .low, .code = .cap_exec, .message = "process execution: addSystemCommand", .location = "build.zig:1" },
    });

    var bl = try Baseline.load(arena, aw.written());

    // A fresh run: the same cap_exec (now on line 3) plus a NEW unpinned finding.
    const findings = [_]Finding{
        .{ .package = "wuffs", .severity = .low, .code = .cap_exec, .message = "process execution: addSystemCommand", .location = "build.zig:3" },
        .{ .package = "depa", .severity = .high, .code = .unpinned, .message = "declares a url but no hash" },
    };
    const kept = try bl.suppress(arena, &findings);

    try testing.expectEqual(@as(usize, 1), kept.len);
    try testing.expectEqual(integrity.Code.unpinned, kept[0].code);
    try testing.expectEqual(@as(usize, 0), bl.staleCount());
}

test "staleCount reports baseline entries that no longer match" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try serialize(arena, &aw.writer, &.{
        .{ .package = "gone", .severity = .high, .code = .unpinned, .message = "declares a url but no hash" },
    });
    var bl = try Baseline.load(arena, aw.written());

    // Nothing in this run matches the baselined finding (it was fixed).
    const kept = try bl.suppress(arena, &.{});
    try testing.expectEqual(@as(usize, 0), kept.len);
    try testing.expectEqual(@as(usize, 1), bl.staleCount());
}

test "load rejects a malformed baseline" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.MalformedBaseline, Baseline.load(arena_state.allocator(), "{not json"));
}
