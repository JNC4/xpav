//! Build tasks for xpav.
//!
//! This tool handles cross-compilation of eBPF programs to the BPF target.
//!
//! Usage:
//!   cargo xtask build-ebpf         # Build eBPF programs (debug)
//!   cargo xtask build-ebpf --release  # Build eBPF programs (release)

use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build tasks for xpav")]
enum Cli {
    /// Build eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Enable eBPF feature
        #[arg(long, default_value = "true")]
        ebpf: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::Build { release, ebpf } => {
            if ebpf {
                build_ebpf(release)?;
            }
            build_userspace(release, ebpf)
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("xpav-ebpf");

    if !ebpf_dir.exists() {
        bail!("xpav-ebpf directory not found at {}", ebpf_dir.display());
    }

    println!("Building eBPF programs...");

    // Ensure target directory exists
    let target_bpf_dir = workspace_root.join("target/bpf");
    fs::create_dir_all(&target_bpf_dir)
        .context("Failed to create target/bpf directory")?;

    // Build the eBPF programs
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root);

    // Use nightly for build-std
    cmd.arg("+nightly");
    cmd.args(["build", "-p", "xpav-ebpf"]);
    cmd.args(["--target", "bpfel-unknown-none"]);
    cmd.args(["-Z", "build-std=core"]);

    if release {
        cmd.arg("--release");
    }

    // Set target directory to workspace target
    cmd.args(["--target-dir", "target"]);

    println!("Running: {:?}", cmd);

    let status = cmd.status().context("Failed to run cargo build for eBPF")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    // Copy the built program to target/bpf/
    let profile = if release { "release" } else { "debug" };
    let built_path = workspace_root
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("xpav-ebpf");

    let output_path = target_bpf_dir.join("xpav_ebpf.o");

    if built_path.exists() {
        fs::copy(&built_path, &output_path).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                built_path.display(),
                output_path.display()
            )
        })?;
        println!("eBPF program built: {}", output_path.display());
    } else {
        // Try alternative naming
        let alt_path = workspace_root
            .join("target/bpfel-unknown-none")
            .join(profile)
            .join("xpav_ebpf");

        if alt_path.exists() {
            fs::copy(&alt_path, &output_path)?;
            println!("eBPF program built: {}", output_path.display());
        } else {
            bail!(
                "Built eBPF program not found. Looked for:\n  {}\n  {}",
                built_path.display(),
                alt_path.display()
            );
        }
    }

    Ok(())
}

fn build_userspace(release: bool, with_ebpf: bool) -> Result<()> {
    let workspace_root = workspace_root()?;

    println!("Building userspace...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root);
    cmd.args(["build", "-p", "xpav"]);

    if release {
        cmd.arg("--release");
    }

    if with_ebpf {
        cmd.args(["--features", "ebpf-native"]);
    }

    let status = cmd.status().context("Failed to run cargo build")?;
    if !status.success() {
        bail!("Userspace build failed");
    }

    println!("Build complete!");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    // xtask is run from the workspace root via `cargo xtask`
    // CARGO_MANIFEST_DIR points to xtask/, so we go up one level
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set")?;

    let xtask_dir = PathBuf::from(manifest_dir);
    let workspace_root = xtask_dir
        .parent()
        .context("Could not find workspace root")?
        .to_path_buf();

    Ok(workspace_root)
}
