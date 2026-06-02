//! Software Bill of Materials export, in CycloneDX 1.6 and SPDX 2.3 (JSON).
//!
//! Both formats describe the same thing: the set of unique packages in the
//! resolved dependency graph and the edges between them. We flatten the resolver
//! tree (which dedups shared subtrees) into a unique component list plus a
//! dependency edge list, then serialize.
//!
//! Two zonar-specific choices, both honest about Zig's model:
//!   * A package's identity is its content hash, so the hash is the natural
//!     component reference. We carry it as the CycloneDX `bom-ref` when present.
//!   * That hash is NOT a standard SHA-256 digest, so it must not masquerade as
//!     one in a `hashes`/`checksums` field. We record it as a namespaced
//!     property (CycloneDX) or the package comment (SPDX) instead.
//!
//! CycloneDX output is reproducible (no timestamp or serial number). SPDX
//! requires a unique document namespace and a creation timestamp, so its output
//! deliberately is not byte-reproducible.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Writer = std.Io.Writer;

const resolver = @import("resolver.zig");
const integrity = @import("integrity.zig");
const json = @import("json.zig");
const Finding = integrity.Finding;

const tool_name = "zonar";
const tool_version = "0.1.0";

const Component = struct {
    name: []const u8,
    version: ?[]const u8,
    kind: resolver.Kind,
    url: ?[]const u8,
    hash: ?[]const u8,
    path: ?[]const u8,
    /// Package URL, e.g. `pkg:generic/foo@1.2.3?download_url=...`.
    purl: []const u8,
    /// CycloneDX bom-ref: the content hash when known, else the purl, made
    /// unique across the BOM.
    ref: []const u8,
};

/// A flattened view of the dependency graph: `components[0]` is the root project;
/// `deps[i]` holds the indices of `components[i]`'s direct dependencies.
const Graph = struct {
    components: []const Component,
    deps: []const []const usize,
};

const Builder = struct {
    arena: Allocator,
    components: std.ArrayListUnmanaged(Component) = .empty,
    deps: std.ArrayListUnmanaged(std.ArrayListUnmanaged(usize)) = .empty,
    index_of: std.StringHashMapUnmanaged(usize) = .empty,
    used_refs: std.StringHashMapUnmanaged(void) = .empty,

    fn identity(node: resolver.Node) []const u8 {
        return node.hash orelse node.dir orelse node.name;
    }

    /// Add `node` as a component if its identity is new; return its index either way.
    fn intern(b: *Builder, node: resolver.Node) !usize {
        const id = identity(node);
        if (b.index_of.get(id)) |i| return i;
        const idx = b.components.items.len;
        try b.index_of.put(b.arena, id, idx);
        try b.components.append(b.arena, try b.componentOf(node));
        try b.deps.append(b.arena, .empty);
        return idx;
    }

    fn addEdge(b: *Builder, parent: usize, child: usize) !void {
        const list = &b.deps.items[parent];
        for (list.items) |e| {
            if (e == child) return; // dedup parallel edges
        }
        try list.append(b.arena, child);
    }

    fn expand(b: *Builder, node: resolver.Node, idx: usize) !void {
        for (node.children) |child| {
            const before = b.components.items.len;
            const cidx = try b.intern(child);
            try b.addEdge(idx, cidx);
            // Newly interned (index == prior length) => first occurrence; recurse.
            if (cidx == before) try b.expand(child, cidx);
        }
    }

    fn componentOf(b: *Builder, node: resolver.Node) !Component {
        const purl = try purlOf(b.arena, node);
        return .{
            .name = node.name,
            .version = node.version,
            .kind = node.kind,
            .url = node.url,
            .hash = node.hash,
            .path = node.path,
            .purl = purl,
            .ref = try b.uniqueRef(node.hash orelse purl),
        };
    }

    fn uniqueRef(b: *Builder, base: []const u8) ![]const u8 {
        if (!b.used_refs.contains(base)) {
            try b.used_refs.put(b.arena, base, {});
            return base;
        }
        var n: usize = 2;
        while (true) : (n += 1) {
            const candidate = try std.fmt.allocPrint(b.arena, "{s}#{d}", .{ base, n });
            if (!b.used_refs.contains(candidate)) {
                try b.used_refs.put(b.arena, candidate, {});
                return candidate;
            }
        }
    }

    fn finish(b: *Builder) Graph {
        const deps = b.arena.alloc([]const usize, b.deps.items.len) catch unreachable;
        for (b.deps.items, 0..) |*d, i| deps[i] = d.items;
        return .{ .components = b.components.items, .deps = deps };
    }
};

fn buildGraph(arena: Allocator, tree: resolver.Tree) !Graph {
    var b: Builder = .{ .arena = arena };
    const root_idx = try b.intern(tree.root); // index 0
    try b.expand(tree.root, root_idx);
    return b.finish();
}

/// Percent-encode per RFC 3986 unreserved set, for purl name/qualifier values.
fn percentEncode(arena: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (s) |c| {
        const unreserved = std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
        if (unreserved) {
            try out.append(arena, c);
        } else {
            try out.print(arena, "%{X:0>2}", .{c});
        }
    }
    return out.items;
}

fn purlOf(arena: Allocator, node: resolver.Node) ![]const u8 {
    const name = try percentEncode(arena, node.name);
    const ver = if (node.version) |v|
        try std.fmt.allocPrint(arena, "@{s}", .{try percentEncode(arena, v)})
    else
        "";
    const dl = if (node.url) |u|
        try std.fmt.allocPrint(arena, "?download_url={s}", .{try percentEncode(arena, u)})
    else
        "";
    return std.fmt.allocPrint(arena, "pkg:generic/{s}{s}{s}", .{ name, ver, dl });
}

/// Findings whose `package` matches `name`. Used to annotate SBOM components.
fn findingsForName(arena: Allocator, findings: []const Finding, name: []const u8) ![]const Finding {
    var out: std.ArrayListUnmanaged(Finding) = .empty;
    for (findings) |f| {
        if (std.mem.eql(u8, f.package, name)) try out.append(arena, f);
    }
    return out.items;
}

// ---------------------------------------------------------------------------
// CycloneDX 1.6
// ---------------------------------------------------------------------------

pub fn renderCycloneDx(
    arena: Allocator,
    out: *Writer,
    tree: resolver.Tree,
    findings: []const Finding,
) !void {
    const g = try buildGraph(arena, tree);

    try out.writeAll("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1,\"metadata\":{");
    try out.print("\"tools\":{{\"components\":[{{\"type\":\"application\",\"name\":\"{s}\",\"version\":\"{s}\"}}]}},", .{ tool_name, tool_version });
    try out.writeAll("\"component\":");
    try writeCycloneComponent(arena, out, g.components[0], "application", findings);
    try out.writeAll("},\"components\":[");
    for (g.components[1..], 1..) |comp, i| {
        if (i != 1) try out.writeAll(",");
        try writeCycloneComponent(arena, out, comp, "library", findings);
    }
    try out.writeAll("],\"dependencies\":[");
    for (g.deps, 0..) |dep_idxs, i| {
        if (i != 0) try out.writeAll(",");
        try out.writeAll("{\"ref\":");
        try json.writeString(out, g.components[i].ref);
        try out.writeAll(",\"dependsOn\":[");
        for (dep_idxs, 0..) |c, j| {
            if (j != 0) try out.writeAll(",");
            try json.writeString(out, g.components[c].ref);
        }
        try out.writeAll("]}");
    }
    try out.writeAll("]}\n");
}

fn writeCycloneComponent(
    arena: Allocator,
    out: *Writer,
    comp: Component,
    comp_type: []const u8,
    findings: []const Finding,
) !void {
    try out.writeAll("{\"bom-ref\":");
    try json.writeString(out, comp.ref);
    try out.print(",\"type\":\"{s}\",\"name\":", .{comp_type});
    try json.writeString(out, comp.name);
    try json.optionalField(out, "version", comp.version);
    try out.writeAll(",\"purl\":");
    try json.writeString(out, comp.purl);

    // Properties: the Zig hash (carried faithfully, not as a fake checksum),
    // the dependency kind, and any zonar findings for this package.
    try out.writeAll(",\"properties\":[");
    var first = true;
    try writeProperty(out, &first, "zonar:kind", @tagName(comp.kind));
    if (comp.hash) |h| try writeProperty(out, &first, "zonar:zig-hash", h);
    for (try findingsForName(arena, findings, comp.name)) |f| {
        const key = try std.fmt.allocPrint(arena, "zonar:finding:{s}", .{f.code.slug()});
        try writeProperty(out, &first, key, f.message);
    }
    try out.writeAll("]");

    if (comp.url) |u| {
        try out.writeAll(",\"externalReferences\":[{\"type\":\"distribution\",\"url\":");
        try json.writeString(out, u);
        try out.writeAll("}]");
    }
    try out.writeAll("}");
}

fn writeProperty(out: *Writer, first: *bool, name: []const u8, value: []const u8) !void {
    if (!first.*) try out.writeAll(",");
    first.* = false;
    try out.writeAll("{\"name\":");
    try json.writeString(out, name);
    try out.writeAll(",\"value\":");
    try json.writeString(out, value);
    try out.writeAll("}");
}

// ---------------------------------------------------------------------------
// SPDX 2.3
// ---------------------------------------------------------------------------

pub fn renderSpdx(
    arena: Allocator,
    io: Io,
    out: *Writer,
    tree: resolver.Tree,
    findings: []const Finding,
) !void {
    const g = try buildGraph(arena, tree);
    const root_name = g.components[0].name;
    const namespace = try std.fmt.allocPrint(arena, "https://spdx.org/spdxdocs/{s}-{s}", .{ root_name, try uuidV4(arena, io) });
    const created = try iso8601(arena, std.Io.Timestamp.now(io, .real).toSeconds());

    try out.writeAll("{\"spdxVersion\":\"SPDX-2.3\",\"dataLicense\":\"CC0-1.0\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":");
    try json.writeString(out, try std.fmt.allocPrint(arena, "{s}-sbom", .{root_name}));
    try out.writeAll(",\"documentNamespace\":");
    try json.writeString(out, namespace);
    try out.print(",\"creationInfo\":{{\"created\":\"{s}\",\"creators\":[\"Tool: {s}-{s}\"]}},", .{ created, tool_name, tool_version });

    try out.writeAll("\"packages\":[");
    for (g.components, 0..) |comp, i| {
        if (i != 0) try out.writeAll(",");
        try writeSpdxPackage(arena, out, i, comp, findings);
    }

    try out.writeAll("],\"relationships\":[");
    // The document describes the root package.
    try out.writeAll("{\"spdxElementId\":\"SPDXRef-DOCUMENT\",\"relationshipType\":\"DESCRIBES\",\"relatedSpdxElement\":\"SPDXRef-pkg-0\"}");
    for (g.deps, 0..) |dep_idxs, i| {
        for (dep_idxs) |c| {
            try out.print(
                ",{{\"spdxElementId\":\"SPDXRef-pkg-{d}\",\"relationshipType\":\"DEPENDS_ON\",\"relatedSpdxElement\":\"SPDXRef-pkg-{d}\"}}",
                .{ i, c },
            );
        }
    }
    try out.writeAll("]}\n");
}

fn writeSpdxPackage(
    arena: Allocator,
    out: *Writer,
    index: usize,
    comp: Component,
    findings: []const Finding,
) !void {
    try out.print("{{\"SPDXID\":\"SPDXRef-pkg-{d}\",\"name\":", .{index});
    try json.writeString(out, comp.name);
    try json.optionalField(out, "versionInfo", comp.version);
    try out.writeAll(",\"downloadLocation\":");
    try json.writeString(out, comp.url orelse "NOASSERTION");
    try out.writeAll(",\"externalRefs\":[{\"referenceCategory\":\"PACKAGE-MANAGER\",\"referenceType\":\"purl\",\"referenceLocator\":");
    try json.writeString(out, comp.purl);
    try out.writeAll("}]");

    // SPDX checksum algorithms are a fixed set that excludes Zig's hash, so the
    // hash and any findings go in the freeform package comment.
    var comment: std.ArrayListUnmanaged(u8) = .empty;
    if (comp.hash) |h| try comment.print(arena, "zig-hash: {s}", .{h});
    for (try findingsForName(arena, findings, comp.name)) |f| {
        if (comment.items.len != 0) try comment.appendSlice(arena, "; ");
        try comment.print(arena, "{s}: {s}", .{ f.code.slug(), f.message });
    }
    if (comment.items.len != 0) {
        try out.writeAll(",\"comment\":");
        try json.writeString(out, comment.items);
    }
    try out.writeAll("}");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn uuidV4(arena: Allocator, io: Io) ![]const u8 {
    var b: [16]u8 = undefined;
    io.random(&b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    return std.fmt.allocPrint(arena, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    });
}

fn iso8601(arena: Allocator, epoch_secs: i64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(epoch_secs) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        md.month.numeric(),
        @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleTree() resolver.Tree {
    // demo -> { a (hash, depends on b), b (hash) }, with a duplicate edge demo->b
    // to exercise dedup. Built as a static tree.
    const b_node: resolver.Node = .{
        .name = "b",
        .version = "2.0.0",
        .kind = .url,
        .url = "https://ex/b.tar.gz",
        .hash = "b-2.0.0-BBBB",
        .status = .ok,
    };
    return .{ .root = .{
        .name = "demo",
        .version = "0.1.0",
        .kind = .root,
        .status = .ok,
        .children = &.{
            .{
                .name = "a",
                .version = "1.0.0",
                .kind = .url,
                .url = "https://ex/a.tar.gz",
                .hash = "a-1.0.0-AAAA",
                .status = .ok,
                .children = &.{b_node},
            },
            b_node,
        },
    } };
}

test "CycloneDX is well-formed and uses the hash as bom-ref" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const findings = [_]Finding{.{ .package = "a", .severity = .high, .code = .unpinned, .message = "no hash" }};

    var aw: Writer.Allocating = .init(arena);
    try renderCycloneDx(arena, &aw.writer, sampleTree(), &findings);

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expectEqualStrings("CycloneDX", root.get("bomFormat").?.string);
    try testing.expectEqualStrings("1.6", root.get("specVersion").?.string);

    const comps = root.get("components").?.array;
    try testing.expectEqual(@as(usize, 2), comps.items.len); // a, b (root is metadata)

    // First component is `a`, bom-ref is its hash, purl is pkg:generic.
    const a = comps.items[0].object;
    try testing.expectEqualStrings("a-1.0.0-AAAA", a.get("bom-ref").?.string);
    try testing.expectEqualStrings("pkg:generic/a@1.0.0?download_url=https%3A%2F%2Fex%2Fa.tar.gz", a.get("purl").?.string);

    // The unpinned finding rode along as a property.
    var saw_finding = false;
    for (a.get("properties").?.array.items) |p| {
        if (std.mem.eql(u8, p.object.get("name").?.string, "zonar:finding:unpinned")) saw_finding = true;
    }
    try testing.expect(saw_finding);
}

test "CycloneDX dedups a diamond but keeps both edges" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try renderCycloneDx(arena, &aw.writer, sampleTree(), &.{});
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});

    // b appears once as a component...
    try testing.expectEqual(@as(usize, 2), parsed.value.object.get("components").?.array.items.len);
    // ...but the demo->b and a->b edges both exist.
    var demo_to_b = false;
    var a_to_b = false;
    for (parsed.value.object.get("dependencies").?.array.items) |d| {
        const ref = d.object.get("ref").?.string;
        for (d.object.get("dependsOn").?.array.items) |dep| {
            if (std.mem.eql(u8, dep.string, "b-2.0.0-BBBB")) {
                if (std.mem.eql(u8, ref, "a-1.0.0-AAAA")) a_to_b = true;
                if (std.mem.eql(u8, ref, "b-2.0.0-BBBB")) {} else if (std.mem.indexOf(u8, ref, "demo") != null) demo_to_b = true;
            }
        }
    }
    try testing.expect(a_to_b);
    try testing.expect(demo_to_b);
}

test "CycloneDX output is reproducible" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var a1: Writer.Allocating = .init(arena);
    var a2: Writer.Allocating = .init(arena);
    try renderCycloneDx(arena, &a1.writer, sampleTree(), &.{});
    try renderCycloneDx(arena, &a2.writer, sampleTree(), &.{});
    try testing.expectEqualStrings(a1.written(), a2.written());
}

test "SPDX is well-formed with required fields and DEPENDS_ON" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var aw: Writer.Allocating = .init(arena);
    try renderSpdx(arena, std.testing.io, &aw.writer, sampleTree(), &.{});

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, aw.written(), .{});
    const root = parsed.value.object;
    try testing.expectEqualStrings("SPDX-2.3", root.get("spdxVersion").?.string);
    try testing.expectEqualStrings("CC0-1.0", root.get("dataLicense").?.string);
    try testing.expect(root.get("documentNamespace").?.string.len > 0);
    try testing.expect(root.get("creationInfo").?.object.get("created") != null);
    try testing.expectEqual(@as(usize, 3), root.get("packages").?.array.items.len); // demo, a, b

    var saw_depends_on = false;
    for (root.get("relationships").?.array.items) |r| {
        if (std.mem.eql(u8, r.object.get("relationshipType").?.string, "DEPENDS_ON")) saw_depends_on = true;
    }
    try testing.expect(saw_depends_on);
}

test "iso8601 formats a known epoch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // 2021-01-01T00:00:00Z = 1609459200
    const s = try iso8601(arena_state.allocator(), 1609459200);
    try testing.expectEqualStrings("2021-01-01T00:00:00Z", s);
}
