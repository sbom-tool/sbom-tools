//! Dagger CI for the Linux FFI and Go bindings.

use dagger_sdk::{
    CacheSharingMode, Container, ContainerWithMountedCacheOpts, DaggerConn, Directory, File,
    HostDirectoryOpts,
};

const RUST_VERSION: &str = "1.88.0";
const TARGET_DIR: &str = "/build/target";
const RELEASE_STATICLIB: &str = "/out/libsbom_tools_ffi.a";
const GO_STATICLIB: &str = "/src/target/release/libsbom_tools_ffi.a";
const WORKSPACE_CHECK: &str = "cargo check --locked";
const FFI_CHECK: &str = "cargo check --locked -p sbom-tools-ffi";
const DEBUG_BUILD: &str = "cargo build --locked -p sbom-tools-ffi";
const ABI_TESTS: &str = "cargo test --locked --profile dev --features ffi \
    --test ffi_bindings --test ffi_schema_snapshots --test conformance_ffi \
    --test ffi_regression --test ffi_compliance";

fn target_cache(
    client: &DaggerConn,
    rust: &Container,
    target_key: &str,
    profile: &str,
) -> Container {
    rust.with_env_variable("CARGO_TARGET_DIR", TARGET_DIR)
        .with_mounted_cache_opts(
            TARGET_DIR,
            client.cache_volume(format!("{target_key}-{profile}")),
            ContainerWithMountedCacheOpts {
                sharing: Some(CacheSharingMode::Locked),
                source: None,
                owner: None,
                expand: None,
            },
        )
}

fn run_rust(rust: &Container, profile: &str, commands: &str) -> Container {
    // Cargo uses source mtimes to validate local crates. Rebuild those crates
    // from the current snapshot and reuse compiled registry dependencies.
    // Keep cleanup and compilation in one exec so the volume stays locked.
    rust.with_exec(vec![
        "bash".to_owned(),
        "-ec".to_owned(),
        format!(
            "cargo clean --locked --profile {profile} -p sbom-tools -p sbom-tools-ffi\n{commands}"
        ),
    ])
}

fn release_staticlib(rust: &Container) -> Container {
    run_rust(
        &rust
            .with_env_variable("CARGO_PROFILE_RELEASE_LTO", "off")
            .with_env_variable("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16"),
        "release",
        &format!(
            "cargo build --locked -p sbom-tools-ffi --release -j 1\n\
             install -Dm644 {TARGET_DIR}/release/libsbom_tools_ffi.a {RELEASE_STATICLIB}"
        ),
    )
}

fn go_tests(client: &DaggerConn, source: Directory, staticlib: File) -> Container {
    client
        .container()
        .from("golang:1.22")
        .with_mounted_directory("/src", source)
        .with_file(GO_STATICLIB, staticlib)
        .with_workdir("/src/bindings/go")
        .with_exec(vec![
            "bash",
            "-ec",
            "go test ./...\nbash /src/scripts/test-bindings-dedup.sh go",
        ])
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ci-all".to_string());

    dagger_sdk::connect(move |client| {
        let command = command.clone();
        async move {
            let platform = client.default_platform().await?.0;
            let target_key = format!("sbom-tools-ffi-target-v2-{RUST_VERSION}-{platform}");
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
                .from(format!("rust:{RUST_VERSION}"))
                .with_env_variable("RUSTUP_TOOLCHAIN", RUST_VERSION)
                // Cargo's package-cache lock lives alongside its registry and git caches.
                .with_env_variable("CARGO_HOME", "/build/cargo")
                .with_mounted_cache(
                    "/build/cargo",
                    client.cache_volume("sbom-tools-cargo-home-v2"),
                )
                .with_mounted_directory("/src", host_source.clone())
                .with_workdir("/src");

            let dev = target_cache(&client, &rust, &target_key, "dev")
                .with_env_variable("CARGO_BUILD_JOBS", "2")
                .with_env_variable("CARGO_PROFILE_DEV_DEBUG", "0")
                .with_env_variable("CARGO_PROFILE_DEV_CODEGEN_UNITS", "16");
            let release = target_cache(&client, &rust, &target_key, "release");

            let output = match command.as_str() {
                "check-workspace" => run_rust(&dev, "dev", WORKSPACE_CHECK).stdout().await?,
                "check-ffi-crate" => run_rust(&dev, "dev", FFI_CHECK).stdout().await?,
                "build-staticlib" => run_rust(&dev, "dev", DEBUG_BUILD).stdout().await?,
                "release-staticlib" => release_staticlib(&release).stdout().await?,
                "test-abi" => run_rust(&dev, "dev", ABI_TESTS).stdout().await?,
                "test-go" => {
                    let staticlib = release_staticlib(&release).file(RELEASE_STATICLIB);
                    go_tests(&client, host_source, staticlib).stdout().await?
                }
                "ci-all" => {
                    let checks = run_rust(
                        &dev,
                        "dev",
                        &format!("{WORKSPACE_CHECK}\n{FFI_CHECK}\n{DEBUG_BUILD}\n{ABI_TESTS}"),
                    );
                    let staticlib = release_staticlib(&release).file(RELEASE_STATICLIB);
                    let go = go_tests(&client, host_source, staticlib);
                    let (checks_output, go_output) =
                        tokio::try_join!(checks.stdout(), go.stdout())?;
                    println!("{checks_output}");
                    go_output
                }
                other => {
                    return Err(eyre::eyre!(
                        "unknown command '{other}'. Supported commands: \
                         check-workspace, check-ffi-crate, build-staticlib, \
                         release-staticlib, test-abi, test-go, ci-all"
                    ));
                }
            };
            println!("{output}");
            Ok(())
        }
    })
    .await?;

    Ok(())
}
