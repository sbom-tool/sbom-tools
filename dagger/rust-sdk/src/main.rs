//! Dagger CI/CD pipeline for sbom-tools FFI bindings.
//!
//! This pipeline orchestrates:
//! - Workspace isolation verification (root crate compiles without FFI symbols)
//! - FFI crate compilation (debug and release static libraries)
//! - Comprehensive FFI test suite (ABI, conformance, regression, contracts)
//! - Go binding testing (cross-compilation with pre-built Rust library)
//!
//! Commands:
//!   check-workspace      Verify root crate compiles without FFI symbols
//!   check-ffi-crate      Verify FFI crate compiles with feature enabled
//!   build-staticlib      Build debug static library
//!   release-staticlib    Build release static library
//!   test-abi             Run all ABI tests (bindings, snapshots, conformance, regression, compliance)
//!   test-go              Build release lib and run Go binding tests
//!   ci-all               Full pipeline: check → build → release → test-abi → test-go

use dagger_sdk::HostDirectoryOpts;

const RELEASE_STATICLIB_PATH: &str = "/src/target/release/libsbom_tools_ffi.a";

fn command_name() -> String {
    std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ci-all".to_string())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let command = command_name();

    dagger_sdk::connect(move |client| {
        let command = command.clone();
        async move {
            let host_source = client.host().directory_opts(
                ".",
                HostDirectoryOpts {
                    exclude: Some(vec![
                        ".git",
                        "target",
                        "bindings/swift/.build",
                        "bindings/swift/.swiftpm",
                    ]),
                    include: None,
                    no_cache: None,
                    gitignore: Some(true),
                },
            );

            let rust = client
                .container()
                .from("rust:1.88")
                .with_mounted_directory("/src", host_source.clone())
                .with_workdir("/src");

            // Release builds only need to produce a testable staticlib for bindings CI.
            // Disable expensive profile optimizations here to keep container memory bounded.
            let rust_release = rust
                .with_env_variable("CARGO_PROFILE_RELEASE_LTO", "off")
                .with_env_variable("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16");

            let rust_test = rust
                .with_env_variable("CARGO_PROFILE_DEV_DEBUG", "0")
                .with_env_variable("CARGO_PROFILE_TEST_DEBUG", "0")
                .with_env_variable("CARGO_PROFILE_TEST_CODEGEN_UNITS", "16");

            match command.as_str() {
                "check-workspace" => {
                    // Verify root crate compiles without FFI symbols.
                    // This ensures workspace isolation: ffi module is not compiled into the main lib.
                    let output = rust.with_exec(vec!["cargo", "check"]).stdout().await?;
                    println!("{output}");
                }
                "check-ffi-crate" => {
                    // Verify FFI crate compiles with feature enabled.
                    let output = rust
                        .with_exec(vec!["cargo", "check", "-p", "sbom-tools-ffi"])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "build-staticlib" => {
                    // Build debug static library.
                    // Crate: sbom-tools-ffi with crate-type ["cdylib", "staticlib"]
                    let output = rust
                        .with_exec(vec!["cargo", "build", "-p", "sbom-tools-ffi"])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "release-staticlib" => {
                    // Build release static library.
                    // Crate: sbom-tools-ffi with crate-type ["cdylib", "staticlib"].
                    // Serialize the release build to keep peak memory within CI container limits.
                    let output = rust_release
                        .with_exec(vec![
                            "cargo",
                            "build",
                            "-p",
                            "sbom-tools-ffi",
                            "--release",
                            "-j",
                            "1",
                        ])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "test-abi" => {
                    // Run all FFI ABI test suites:
                    // 1. ffi_bindings — basic ABI functionality
                    // 2. ffi_schema_snapshots — contract keys and header signatures
                    // 3. conformance_ffi — bidirectional spec↔runtime conformance (10 tests)
                    // 4. ffi_regression — multi-format parsing and edge cases (8 tests)
                    // 5. ffi_compliance — validate and the rule catalogue against the CLI
                    let output = rust_test
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_bindings",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_schema_snapshots",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "conformance_ffi",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_regression",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_compliance",
                        ])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "test-go" => {
                    // Build release static library in Rust container, then run Go tests in golang:1.22.
                    let rust_with_lib = rust_release.with_exec(vec![
                        "cargo",
                        "build",
                        "-p",
                        "sbom-tools-ffi",
                        "--release",
                        "-j",
                        "1",
                    ]);

                    // Export the compiled staticlib from Rust container.
                    let staticlib = rust_with_lib.file(RELEASE_STATICLIB_PATH);

                    // Create Go test container.
                    // The CGo build in bindings/go expects:
                    //   LDFLAGS: -L../../target/release -lsbom_tools_ffi
                    // From /src/bindings/go, ../../target/release = /src/target/release ✓
                    let output = client
                        .container()
                        .from("golang:1.22")
                        .with_mounted_directory("/src", host_source)
                        .with_file(RELEASE_STATICLIB_PATH, staticlib)
                        .with_workdir("/src/bindings/go")
                        .with_exec(vec!["go", "test", "./..."])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "ci-all" => {
                    // Full CI pipeline:
                    // 1. check-workspace — verify root crate isolation
                    // 2. check-ffi-crate — verify FFI crate compiles
                    // 3. build-staticlib — build debug lib
                    // 4. release-staticlib — build release lib
                    // 5. test-abi — run all FFI tests
                    // 6. test-go — run Go binding tests

                    // Step 1: check-workspace
                    let rust = rust.with_exec(vec!["cargo", "check"]);

                    // Step 2: check-ffi-crate
                    let rust = rust.with_exec(vec!["cargo", "check", "-p", "sbom-tools-ffi"]);

                    // Step 3: build-staticlib
                    let rust = rust.with_exec(vec!["cargo", "build", "-p", "sbom-tools-ffi"]);

                    // Step 4: release-staticlib
                    let rust = rust
                        .with_env_variable("CARGO_PROFILE_RELEASE_LTO", "off")
                        .with_env_variable("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16")
                        .with_exec(vec![
                            "cargo",
                            "build",
                            "-p",
                            "sbom-tools-ffi",
                            "--release",
                            "-j",
                            "1",
                        ]);

                    // Step 5: test-abi (all 5 test suites)
                    let rust = rust
                        .with_env_variable("CARGO_PROFILE_DEV_DEBUG", "0")
                        .with_env_variable("CARGO_PROFILE_TEST_DEBUG", "0")
                        .with_env_variable("CARGO_PROFILE_TEST_CODEGEN_UNITS", "16")
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_bindings",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_schema_snapshots",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "conformance_ffi",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_regression",
                        ])
                        .with_exec(vec![
                            "cargo",
                            "test",
                            "-j",
                            "1",
                            "--features",
                            "ffi",
                            "--test",
                            "ffi_compliance",
                        ]);

                    // Export the compiled release staticlib from final Rust container.
                    let staticlib = rust.file(RELEASE_STATICLIB_PATH);

                    // Step 6: test-go (in golang:1.22 container)
                    let output = client
                        .container()
                        .from("golang:1.22")
                        .with_mounted_directory("/src", host_source)
                        .with_file(RELEASE_STATICLIB_PATH, staticlib)
                        .with_workdir("/src/bindings/go")
                        .with_exec(vec!["go", "test", "./..."])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                other => {
                    return Err(eyre::eyre!(
                        "unknown command '{other}'. Supported commands:\n  \
                         check-workspace\n  \
                         check-ffi-crate\n  \
                         build-staticlib\n  \
                         release-staticlib\n  \
                         test-abi\n  \
                         test-go\n  \
                         ci-all"
                    ));
                }
            }

            Ok(())
        }
    })
    .await?;

    Ok(())
}
