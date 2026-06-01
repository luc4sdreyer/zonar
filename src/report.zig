//! Rendering: a human-readable dependency tree with inline integrity
//! annotations, and a stable JSON document for tooling. Both write to a
//! `std.Io.Writer`; neither allocates beyond what inline finding messages need.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

const resolver = @import("resolver.zig");
const integrity = @import("integrity.zig");
const Finding = integrity.Finding;
const Severity = integrity.Severity;

pub const Counts = struct {
    info: usize = 0,
    low: usize = 0,
    high: usize = 0,
    critical: usize = 0,

    pub fn add(self: *Counts, sev: Severity) void {
        switch (sev) {
            .info => self.info += 1,
            .low => self.low += 1,
            .high => self.high += 1,
            .critical => self.critical += 1,
        }
    }

    pub fn tally(findings: []const Finding) Counts {
        var c: Counts = .{};
        for (findings) |f| c.add(f.severity);
        return c;
    }

    /// The most severe finding present, or null if there are none.
    pub fn worst(self: Counts) ?Severity {
        if (self.critical > 0) return .critical;
        if (self.high > 0) return .high;
        if (self.low > 0) return .low;
        if (self.info > 0) return .info;
        return null;
    }
};

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

pub fn renderText(
    arena: Allocator,
    out: *Writer,
    tree: resolver.Tree,
    findings: []const Finding,
) !void {
    try out.print("zonar audit — {s}", .{tree.root.name});
    if (tree.root.version) |v| try out.print(" {s}", .{v});
    try out.writeAll("\n");

    try renderChildren(arena, out, tree.root.children, "");

    try out.writeAll("\n");
    if (findings.len == 0) {
        try out.writeAll("No integrity findings.\n");
    } else {
        try out.writeAll("Findings:\n");
        for (findings) |f| {
            if (f.location) |loc| {
                try out.print("  [{s}] {s} ({s}): {s}\n", .{ f.severity.label(), f.package, loc, f.message });
            } else {
                try out.print("  [{s}] {s}: {s}\n", .{ f.severity.label(), f.package, f.message });
            }
        }
    }

    const c = Counts.tally(findings);
    try out.print(
        "\nSummary: {d} critical, {d} high, {d} low, {d} info\n",
        .{ c.critical, c.high, c.low, c.info },
    );
}

fn renderChildren(arena: Allocator, out: *Writer, children: []const resolver.Node, prefix: []const u8) !void {
    for (children, 0..) |child, i| {
        const last = i == children.len - 1;
        try out.writeAll(prefix);
        try out.writeAll(if (last) "└─ " else "├─ ");
        try renderNodeLabel(arena, out, child);
        try out.writeAll("\n");

        if (child.duplicate or child.children.len == 0) continue;
        const child_prefix = try std.fmt.allocPrint(arena, "{s}{s}", .{ prefix, if (last) "   " else "│  " });
        try renderChildren(arena, out, child.children, child_prefix);
    }
}

fn renderNodeLabel(arena: Allocator, out: *Writer, node: resolver.Node) !void {
    try out.print("{s}", .{node.name});
    if (node.version) |v| {
        try out.print(" {s}", .{v});
    } else {
        try out.print(" ({s})", .{@tagName(node.kind)});
    }
    if (node.duplicate) {
        try out.writeAll("  ↻ (already shown)");
        return;
    }

    // Inline annotation from the static integrity checks for this node.
    var buf: std.ArrayList(Finding) = .empty;
    defer buf.deinit(arena);
    try integrity.findingsFor(arena, node, &buf);

    if (buf.items.len == 0) {
        switch (node.status) {
            .ok => if (node.url != null) try out.writeAll("  ✔ pinned"),
            else => {},
        }
        return;
    }

    // Show the most severe finding inline.
    var worst = buf.items[0];
    for (buf.items[1..]) |f| {
        if (f.severity.rank() > worst.severity.rank()) worst = f;
    }
    const glyph = switch (worst.severity) {
        .critical => "✖",
        .high => "⚠",
        .low => "⚠",
        .info => "·",
    };
    try out.print("  {s} {s}", .{ glyph, @tagName(worst.code) });
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

pub fn renderJson(
    out: *Writer,
    tree: resolver.Tree,
    findings: []const Finding,
) !void {
    try out.writeAll("{\"root\":");
    try renderJsonNode(out, tree.root);
    try out.writeAll(",\"findings\":[");
    for (findings, 0..) |f, i| {
        if (i != 0) try out.writeAll(",");
        try out.writeAll("{\"package\":");
        try jsonString(out, f.package);
        try out.print(",\"severity\":\"{s}\",\"code\":\"{s}\",\"message\":", .{ f.severity.label(), f.code.slug() });
        try jsonString(out, f.message);
        try jsonOptionalField(out, "location", f.location);
        try out.writeAll("}");
    }
    const c = Counts.tally(findings);
    try out.print(
        "],\"summary\":{{\"critical\":{d},\"high\":{d},\"low\":{d},\"info\":{d}}}}}",
        .{ c.critical, c.high, c.low, c.info },
    );
    try out.writeAll("\n");
}

fn renderJsonNode(out: *Writer, node: resolver.Node) !void {
    try out.writeAll("{\"name\":");
    try jsonString(out, node.name);
    try out.print(",\"kind\":\"{s}\",\"status\":\"{s}\",\"lazy\":{},\"duplicate\":{}", .{
        @tagName(node.kind), @tagName(node.status), node.lazy, node.duplicate,
    });
    try jsonOptionalField(out, "version", node.version);
    try jsonOptionalField(out, "url", node.url);
    try jsonOptionalField(out, "hash", node.hash);
    try jsonOptionalField(out, "path", node.path);
    try out.writeAll(",\"children\":[");
    for (node.children, 0..) |child, i| {
        if (i != 0) try out.writeAll(",");
        try renderJsonNode(out, child);
    }
    try out.writeAll("]}");
}

fn jsonOptionalField(out: *Writer, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    try out.print(",\"{s}\":", .{key});
    try jsonString(out, v);
}

fn jsonString(out: *Writer, s: []const u8) !void {
    try out.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => if (c < 0x20) {
                try out.print("\\u{x:0>4}", .{c});
            } else {
                try out.writeByte(c);
            },
        }
    }
    try out.writeByte('"');
}

const testing = std.testing;

test "Counts.worst picks the most severe" {
    var c: Counts = .{};
    try testing.expect(c.worst() == null);
    c.add(.info);
    c.add(.high);
    c.add(.low);
    try testing.expectEqual(Severity.high, c.worst().?);
    c.add(.critical);
    try testing.expectEqual(Severity.critical, c.worst().?);
}

test "renderJson produces valid parseable JSON" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tree: resolver.Tree = .{ .root = .{
        .name = "root",
        .version = "0.1.0",
        .kind = .root,
        .children = &.{
            .{ .name = "dep \"x\"", .kind = .url, .url = "https://x/y.tar.gz", .status = .unlocatable },
        },
    } };
    const findings = [_]Finding{.{
        .package = "dep \"x\"",
        .severity = .high,
        .code = .unpinned,
        .message = "no hash\nsecond line",
    }};

    var aw: Writer.Allocating = .init(arena);
    defer aw.deinit();
    try renderJson(&aw.writer, tree, &findings);

    // Round-trip through the JSON parser to prove it is well-formed and escaped.
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("root", parsed.value.object.get("root").?.object.get("name").?.string);
    try testing.expectEqualStrings("dep \"x\"", parsed.value.object.get("findings").?.array.items[0].object.get("package").?.string);
}
