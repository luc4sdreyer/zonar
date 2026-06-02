const std = @import("std");
const Io = std.Io;
const zonar = @import("zonar");

const version = zonar.version;

const usage =
    \\zonar: a supply-chain auditor for the Zig package manager
    \\
    \\Usage:
    \\  zonar audit [path] [options]
    \\
    \\  path                Path to a build.zig.zon (default: ./build.zig.zon)
    \\
    \\Options:
    \\  --json              Emit the audit as JSON instead of a tree
    \\  --sbom=<format>     Emit an SBOM instead of a report (format: cyclonedx | spdx)
    \\  --scan              Scan each dependency's build.zig for risky capabilities
    \\  --verify            Recompute cached deps' content hashes and check them (offline; needs zig)
    \\  --cache <dir>       Override the global package cache directory
    \\  --fail-on=<level>   Exit non-zero at this severity or above
    \\                      (info | low | high | critical | never; default: high)
    \\  -h, --help          Show this help
    \\  -v, --version       Show version
    \\
;

const Sbom = enum { none, cyclonedx, spdx };

const FailOn = enum {
    info,
    low,
    high,
    critical,
    never,

    /// Findings at this rank or above cause a non-zero exit. `never` is a rank
    /// no finding can reach.
    fn threshold(self: FailOn) u8 {
        return switch (self) {
            .info => zonar.Severity.info.rank(),
            .low => zonar.Severity.low.rank(),
            .high => zonar.Severity.high.rank(),
            .critical => zonar.Severity.critical.rank(),
            .never => std.math.maxInt(u8),
        };
    }
};

const Options = struct {
    path: []const u8 = "build.zig.zon",
    json: bool = false,
    sbom: Sbom = .none,
    scan: bool = false,
    verify: bool = false,
    cache_override: ?[]const u8 = null,
    fail_on: FailOn = .high,
};

const ParsedArgs = union(enum) {
    help,
    version,
    audit: Options,
    @"error": []const u8,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_fw: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_fw.interface;

    const args = try init.minimal.args.toSlice(arena);
    const parsed = parseArgs(args);

    switch (parsed) {
        .help => {
            try stderr.writeAll(usage);
            try stderr.flush();
            return;
        },
        .version => {
            try stderr.print("zonar {s}\n", .{version});
            try stderr.flush();
            return;
        },
        .@"error" => |msg| {
            try stderr.print("error: {s}\n\n{s}", .{ msg, usage });
            try stderr.flush();
            std.process.exit(2);
        },
        .audit => |opts| {
            const code = runAudit(arena, io, init.environ_map, opts, stderr) catch |err| {
                try stderr.print("error: {s}\n", .{explain(err)});
                try stderr.flush();
                std.process.exit(1);
            };
            std.process.exit(code);
        },
    }
}

fn parseArgs(args: []const [:0]const u8) ParsedArgs {
    var opts: Options = .{};
    var saw_path = false;
    // args[0] is the program name; an optional first non-flag token may be the
    // subcommand ("audit") which we accept and otherwise ignore for ergonomics.
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) return .version;
        if (std.mem.eql(u8, arg, "--json")) {
            opts.json = true;
        } else if (std.mem.startsWith(u8, arg, "--sbom=")) {
            opts.sbom = std.meta.stringToEnum(Sbom, arg["--sbom=".len..]) orelse
                return .{ .@"error" = "--sbom must be one of: cyclonedx, spdx" };
            if (opts.sbom == .none) return .{ .@"error" = "--sbom must be one of: cyclonedx, spdx" };
        } else if (std.mem.startsWith(u8, arg, "--fail-on=")) {
            opts.fail_on = std.meta.stringToEnum(FailOn, arg["--fail-on=".len..]) orelse
                return .{ .@"error" = "--fail-on must be one of: info, low, high, critical, never" };
        } else if (std.mem.eql(u8, arg, "--scan")) {
            opts.scan = true;
        } else if (std.mem.eql(u8, arg, "--verify")) {
            opts.verify = true;
        } else if (std.mem.eql(u8, arg, "--cache")) {
            i += 1;
            if (i >= args.len) return .{ .@"error" = "--cache requires a directory argument" };
            opts.cache_override = args[i];
        } else if (std.mem.eql(u8, arg, "audit") and i == 1) {
            // Accept an explicit `audit` subcommand.
            continue;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return .{ .@"error" = "unknown option" };
        } else {
            if (saw_path) return .{ .@"error" = "unexpected extra argument" };
            opts.path = arg;
            saw_path = true;
        }
    }
    return .{ .audit = opts };
}

/// Run the audit pipeline. Returns the process exit code (0 = clean, 1 = a
/// high/critical finding was present).
fn runAudit(
    arena: std.mem.Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    opts: Options,
    stderr: *Io.Writer,
) !u8 {
    const cache = try zonar.cache.resolve(arena, io, env, opts.cache_override);
    const tree = try zonar.resolver.resolve(arena, io, cache, opts.path);

    var findings: std.ArrayList(zonar.Finding) = .empty;
    try zonar.integrity.check(arena, tree, &findings);
    if (opts.scan) {
        try zonar.scanner.scanTree(arena, io, tree, &findings);
    }
    if (opts.verify) {
        // `zig fetch` needs a build.zig in its working directory, so run it from
        // the audited project's own directory (the root manifest's dir).
        const project_dir = tree.root.dir orelse ".";
        try zonar.verify.verifyTree(arena, io, project_dir, tree, &findings);
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_fw: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_fw.interface;

    switch (opts.sbom) {
        .cyclonedx => try zonar.sbom.renderCycloneDx(arena, stdout, tree, findings.items),
        .spdx => try zonar.sbom.renderSpdx(arena, io, stdout, tree, findings.items),
        .none => if (opts.json)
            try zonar.report.renderJson(stdout, tree, findings.items)
        else
            try zonar.report.renderText(arena, stdout, tree, findings.items),
    }
    try stdout.flush();
    _ = stderr;

    // Exit code reflects the findings regardless of output format, so an SBOM run
    // can still gate CI via --fail-on.
    const counts = zonar.report.Counts.tally(findings.items);
    if (counts.worst()) |w| {
        if (w.rank() >= opts.fail_on.threshold()) return 1;
    }
    return 0;
}

/// Map an audit error to a message that points the user at the likely cause.
fn explain(err: anyerror) []const u8 {
    return switch (err) {
        error.RootUnreadable => "could not read or parse the root build.zig.zon (check the path)",
        error.ZigEnvFailed => "could not run `zig env` to locate the package cache (is zig on PATH?)",
        error.ZigEnvUnparseable => "could not understand `zig env` output",
        else => @errorName(err),
    };
}

test "parseArgs defaults to audit of ./build.zig.zon" {
    const args = [_][:0]const u8{"zonar"};
    const parsed = parseArgs(&args);
    try std.testing.expect(parsed == .audit);
    try std.testing.expectEqualStrings("build.zig.zon", parsed.audit.path);
    try std.testing.expect(!parsed.audit.json);
}

test "parseArgs reads flags and path" {
    const args = [_][:0]const u8{ "zonar", "audit", "sub/build.zig.zon", "--json", "--verify", "--cache", "/tmp/c" };
    const parsed = parseArgs(&args);
    try std.testing.expect(parsed == .audit);
    try std.testing.expectEqualStrings("sub/build.zig.zon", parsed.audit.path);
    try std.testing.expect(parsed.audit.json);
    try std.testing.expect(parsed.audit.verify);
    try std.testing.expectEqualStrings("/tmp/c", parsed.audit.cache_override.?);
}

test "parseArgs surfaces --cache without value" {
    const args = [_][:0]const u8{ "zonar", "--cache" };
    const parsed = parseArgs(&args);
    try std.testing.expect(parsed == .@"error");
}

test "parseArgs reads --sbom and --fail-on" {
    const parsed = parseArgs(&[_][:0]const u8{ "zonar", "--sbom=cyclonedx", "--fail-on=never" });
    try std.testing.expect(parsed == .audit);
    try std.testing.expectEqual(Sbom.cyclonedx, parsed.audit.sbom);
    try std.testing.expectEqual(FailOn.never, parsed.audit.fail_on);
}

test "parseArgs defaults fail_on to high and sbom to none" {
    const parsed = parseArgs(&[_][:0]const u8{"zonar"});
    try std.testing.expectEqual(Sbom.none, parsed.audit.sbom);
    try std.testing.expectEqual(FailOn.high, parsed.audit.fail_on);
}

test "parseArgs rejects bad --sbom and --fail-on values" {
    try std.testing.expect(parseArgs(&[_][:0]const u8{ "zonar", "--sbom=junk" }) == .@"error");
    try std.testing.expect(parseArgs(&[_][:0]const u8{ "zonar", "--sbom=none" }) == .@"error");
    try std.testing.expect(parseArgs(&[_][:0]const u8{ "zonar", "--fail-on=bogus" }) == .@"error");
}

test "parseArgs recognizes help and version" {
    try std.testing.expect(parseArgs(&[_][:0]const u8{ "zonar", "--help" }) == .help);
    try std.testing.expect(parseArgs(&[_][:0]const u8{ "zonar", "-v" }) == .version);
}
