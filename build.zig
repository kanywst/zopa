const std = @import("std");

// zopa build script.
//
// The shipped artifact is wasm32-freestanding so it can be loaded as
// a proxy-wasm plugin. The host talks to it only through exported
// functions; there is no _start and no libc.
//
// Other Zig projects can also depend on the library entry
// (`src/root.zig`); that's what `b.addModule("zopa", ...)` exposes.
// Unit tests run against the library entry on the host so
// `std.testing.allocator` and friends work.
pub fn build(b: *std.Build) void {
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSmall,
    });

    // Public library entry. Other Zig projects do
    //   .dependencies = .{ .zopa = .{ ... } }
    // and `@import("zopa")` to get this module.
    _ = b.addModule("zopa", .{
        .root_source_file = b.path("src/root.zig"),
    });

    // wasm artifact (`zig-out/bin/zopa.wasm`).
    const exe = b.addExecutable(.{
        .name = "zopa",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = wasm_target,
            .optimize = optimize,
        }),
    });
    exe.entry = .disabled;
    exe.rdynamic = true;
    b.installArtifact(exe);

    // `zig build test-unit` -> Zig's built-in test runner against the
    // library entry on the host, so `std.testing` works.
    const native_target = b.standardTargetOptions(.{});
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = native_target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_unit_step = b.step("test-unit", "Run Zig unit tests on the host");
    test_unit_step.dependOn(&run_unit_tests.step);

    // `zig build test` -> Node-driven integration suite against the
    // freshly installed wasm artifact.
    const node_run = b.addSystemCommand(&.{ "node", "test/run.mjs" });
    node_run.step.dependOn(b.getInstallStep());
    const test_step = b.step("test", "Run integration tests in Node.js");
    test_step.dependOn(&node_run.step);

    // `zig build test-wasmtime` -> same suite via wasmtime + Python.
    // Uses the project-local virtualenv to avoid touching the system
    // Python.
    const wasmtime_run = b.addSystemCommand(&.{
        ".venv-test/bin/python",
        "test/run_wasmtime.py",
    });
    wasmtime_run.step.dependOn(b.getInstallStep());
    const test_wasmtime_step = b.step(
        "test-wasmtime",
        "Run integration tests in wasmtime (Python)",
    );
    test_wasmtime_step.dependOn(&wasmtime_run.step);

    // `zig build test-envoy` -> end-to-end check against a real Envoy.
    // Exercises the proxy-wasm ABI path (configure / request_headers /
    // send_local_response) that the generic-ABI tests can't reach.
    // Invoke through `bash` so we don't depend on the script's
    // execute bit, which can be lost on fresh clones or filesystems
    // that don't preserve mode bits.
    const envoy_run = b.addSystemCommand(&.{ "bash", "examples/envoy/run.sh" });
    envoy_run.step.dependOn(b.getInstallStep());
    const test_envoy_step = b.step(
        "test-envoy",
        "Run end-to-end test against a real Envoy + proxy-wasm",
    );
    test_envoy_step.dependOn(&envoy_run.step);

    // `zig build test-all` -> every suite available on the host.
    const test_all_step = b.step(
        "test-all",
        "Run unit tests and every integration runtime available",
    );
    test_all_step.dependOn(&run_unit_tests.step);
    test_all_step.dependOn(&node_run.step);
    test_all_step.dependOn(&wasmtime_run.step);
    test_all_step.dependOn(&envoy_run.step);

    // `zig build bench` -> Node-based cross-engine benchmark: zopa
    // against OPA-in-wasm and an OPA HTTP sidecar. The OPA engines are
    // skipped (and named) when no `opa` is on PATH, so this step works
    // without one. See bench/README.md.
    const bench_run = b.addSystemCommand(&.{ "node", "bench/run.mjs" });
    bench_run.step.dependOn(b.getInstallStep());
    const bench_step = b.step(
        "bench",
        "Benchmark zopa against OPA (wasm + HTTP sidecar) in Node.js",
    );
    bench_step.dependOn(&bench_run.step);

    // `zig build test-conformance` -> rego (via `opa parse` +
    // tools/rego2ast.py) is fed through zopa.wasm and decisions are
    // compared to fixture expectations. Needs the project venv plus
    // an `opa` CLI on PATH. See test/conformance/README.md.
    const conformance_run = b.addSystemCommand(&.{
        ".venv-test/bin/python",
        "test/conformance/run.py",
    });
    conformance_run.step.dependOn(b.getInstallStep());
    const test_conformance_step = b.step(
        "test-conformance",
        "Run OPA conformance fixtures (rego -> zopa AST -> evaluate)",
    );
    test_conformance_step.dependOn(&conformance_run.step);
}
