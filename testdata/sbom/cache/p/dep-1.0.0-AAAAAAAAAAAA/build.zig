// Fixture build.zig with a capability, so `--scan` adds a finding that rides
// along into the SBOM as a `zonar:finding:cap_exec` property.
const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addSystemCommand(&.{ "echo", "building" });
}
