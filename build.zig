const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Version: single source of truth is build.zig.zon, overridable at release
    // time with `-Dversion=<tag>` so `zonar --version` always matches the release.
    const default_version = @import("build.zig.zon").version;
    const version = b.option([]const u8, "version", "Override the version string") orelse default_version;
    const options = b.addOptions();
    options.addOption([]const u8, "version", version);

    // The library module: the audit engine, importable by consumers and by the CLI.
    const mod = b.addModule("zonar", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    // The library reports its own version in SBOM output, so it carries the
    // version too (consumers get zonar's version baked in).
    mod.addOptions("build_options", options);

    // The CLI executable.
    const exe = b.addExecutable(.{
        .name = "zonar",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zonar", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    // `zig build run [-- args...]`
    const run_step = b.step("run", "Run the zonar CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // `zig build test` — runs unit tests from both the library and the CLI module.
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // `zig build docs` — emit HTML API documentation for the library module into
    // zig-out/docs (deployed to GitHub Pages by .github/workflows/pages.yml).
    const docs_lib = b.addLibrary(.{
        .name = "zonar",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    docs_lib.root_module.addOptions("build_options", options);
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Build the API documentation");
    docs_step.dependOn(&install_docs.step);
}
