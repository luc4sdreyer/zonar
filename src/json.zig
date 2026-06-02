//! Minimal JSON output helpers shared by the audit report and the SBOM
//! exporters. zonar hand-writes JSON (rather than pulling in a dependency — a
//! supply-chain tool keeps its own tree empty), so escaping lives in one place.

const std = @import("std");
const Writer = std.Io.Writer;

/// Write `s` as a quoted, escaped JSON string (including the surrounding quotes).
pub fn writeString(out: *Writer, s: []const u8) !void {
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

/// Write `,"key":<string>` when `value` is non-null; otherwise write nothing.
/// Handy for optional fields in an object that already has a preceding member.
pub fn optionalField(out: *Writer, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    try out.print(",\"{s}\":", .{key});
    try writeString(out, v);
}

const testing = std.testing;

test "writeString escapes control characters and quotes" {
    var aw: Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeString(&aw.writer, "a\"b\\c\n\t\x01");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\n\\t\\u0001\"", aw.written());
}
