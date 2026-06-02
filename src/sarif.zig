//! SARIF 2.1.0 export (`--sarif`). Renders the audit findings as a static
//! analysis results file, so a CI step can upload it and the findings appear in
//! GitHub's Security tab and as pull-request annotations.
//!
//! zonar's findings are about *dependency* files, which do not live in the
//! audited repository, so each result is anchored to the project's own
//! `build.zig.zon` (the file where the dependency was chosen) via a
//! physicalLocation. The dependency is named in a logicalLocation, and the
//! in-package location (`build.zig:42`) is carried in the message text.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

const integrity = @import("integrity.zig");
const json = @import("json.zig");
const Finding = integrity.Finding;
const Severity = integrity.Severity;

const tool_name = "zonar";
const tool_version = @import("build_options").version;
const information_uri = "https://github.com/luc4sdreyer/zonar";
const schema_uri = "https://json.schemastore.org/sarif-2.1.0.json";

/// SARIF result level for a zonar severity. SARIF has only four levels, so high
/// and critical both map to `error`; GitHub's finer bucketing is driven by the
/// `security-severity` property below.
fn level(sev: Severity) []const u8 {
    return switch (sev) {
        .info => "note",
        .low => "warning",
        .high => "error",
        .critical => "error",
    };
}

/// A CVSS-like score GitHub reads to bucket a rule's findings (>= 9 critical,
/// >= 7 high, >= 4 medium, else low).
fn securitySeverity(sev: Severity) []const u8 {
    return switch (sev) {
        .info => "0.0",
        .low => "3.0",
        .high => "7.0",
        .critical => "9.5",
    };
}

/// Render `findings` as a SARIF 2.1.0 log. `manifest_path` is the audited root
/// `build.zig.zon`; results are anchored to it (it is a real file in the repo).
pub fn renderSarif(
    arena: Allocator,
    out: *Writer,
    manifest_path: []const u8,
    findings: []const Finding,
) !void {
    const uri = if (std.mem.startsWith(u8, manifest_path, "./"))
        manifest_path[2..]
    else
        manifest_path;

    try out.print(
        "{{\"version\":\"2.1.0\",\"$schema\":\"{s}\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"{s}\",\"informationUri\":\"{s}\",\"version\":\"{s}\",\"rules\":[",
        .{ schema_uri, tool_name, information_uri, tool_version },
    );

    // One rule per distinct code present, in first-seen order. Keeping this
    // data-driven (no per-code switch) means a new finding code needs no edit
    // here, mirroring how the rest of the codebase avoids exhaustive switches.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var first_rule = true;
    for (findings) |f| {
        const id = f.code.slug();
        if (seen.contains(id)) continue;
        try seen.put(arena, id, {});
        if (!first_rule) try out.writeAll(",");
        first_rule = false;
        try out.writeAll("{\"id\":");
        try json.writeString(out, id);
        try out.writeAll(",\"name\":");
        try json.writeString(out, id);
        try out.print(
            ",\"defaultConfiguration\":{{\"level\":\"{s}\"}},\"properties\":{{\"security-severity\":\"{s}\"}}}}",
            .{ level(f.severity), securitySeverity(f.severity) },
        );
    }

    try out.writeAll("]}},\"results\":[");

    for (findings, 0..) |f, i| {
        if (i != 0) try out.writeAll(",");
        try out.writeAll("{\"ruleId\":");
        try json.writeString(out, f.code.slug());
        try out.print(",\"level\":\"{s}\",\"message\":{{\"text\":", .{level(f.severity)});
        const text = if (f.location) |loc|
            try std.fmt.allocPrint(arena, "{s} ({s}): {s}", .{ f.package, loc, f.message })
        else
            try std.fmt.allocPrint(arena, "{s}: {s}", .{ f.package, f.message });
        try json.writeString(out, text);
        try out.writeAll("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        try json.writeString(out, uri);
        try out.writeAll("}},\"logicalLocations\":[{\"fullyQualifiedName\":");
        try json.writeString(out, f.package);
        try out.writeAll(",\"kind\":\"module\"}]}]}");
    }

    try out.writeAll("]}]}\n");
}

const testing = std.testing;

fn sampleFindings() []const Finding {
    return &.{
        .{ .package = "depa", .severity = .high, .code = .unpinned, .message = "declares a url but no hash" },
        .{ .package = "depb", .severity = .low, .code = .cap_exec, .message = "process execution: addSystemCommand", .location = "build.zig:3" },
        .{ .package = "depb", .severity = .critical, .code = .hash_mismatch, .message = "cached content does not match" },
    };
}

test "renderSarif emits a well-formed 2.1.0 log" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try renderSarif(arena, &aw.writer, "./build.zig.zon", sampleFindings());

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expectEqualStrings("2.1.0", root.get("version").?.string);

    const run = root.get("runs").?.array.items[0].object;
    const driver = run.get("tool").?.object.get("driver").?.object;
    try testing.expectEqualStrings("zonar", driver.get("name").?.string);

    // One rule per distinct code (unpinned, cap_exec, hash_mismatch).
    try testing.expectEqual(@as(usize, 3), driver.get("rules").?.array.items.len);

    const results = run.get("results").?.array;
    try testing.expectEqual(@as(usize, 3), results.items.len);

    // First result: unpinned -> error, message carries the package, anchored to
    // the manifest with the leading "./" stripped.
    const r0 = results.items[0].object;
    try testing.expectEqualStrings("unpinned", r0.get("ruleId").?.string);
    try testing.expectEqualStrings("error", r0.get("level").?.string);
    try testing.expectEqualStrings("depa: declares a url but no hash", r0.get("message").?.object.get("text").?.string);
    const loc0 = r0.get("locations").?.array.items[0].object;
    try testing.expectEqualStrings(
        "build.zig.zon",
        loc0.get("physicalLocation").?.object.get("artifactLocation").?.object.get("uri").?.string,
    );
    try testing.expectEqualStrings(
        "depa",
        loc0.get("logicalLocations").?.array.items[0].object.get("fullyQualifiedName").?.string,
    );

    // A scan finding carries its in-package location in the message text.
    const r1 = results.items[1].object;
    try testing.expectEqualStrings("warning", r1.get("level").?.string);
    try testing.expectEqualStrings(
        "depb (build.zig:3): process execution: addSystemCommand",
        r1.get("message").?.object.get("text").?.string,
    );
}

test "renderSarif maps severities and is valid with no findings" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try renderSarif(arena, &aw.writer, "build.zig.zon", &.{});

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    const run = parsed.value.object.get("runs").?.array.items[0].object;
    try testing.expectEqual(@as(usize, 0), run.get("results").?.array.items.len);
    try testing.expectEqual(@as(usize, 0), run.get("tool").?.object.get("driver").?.object.get("rules").?.array.items.len);
}

test "level and securitySeverity map every severity" {
    try testing.expectEqualStrings("note", level(.info));
    try testing.expectEqualStrings("warning", level(.low));
    try testing.expectEqualStrings("error", level(.high));
    try testing.expectEqualStrings("error", level(.critical));
    try testing.expectEqualStrings("9.5", securitySeverity(.critical));
    try testing.expectEqualStrings("0.0", securitySeverity(.info));
}
