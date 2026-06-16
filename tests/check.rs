// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Run formatting, clippy and tests across all supported targets.
//!
//! Build and run standalone, e.g. `rustc tests/check.rs -o check && ./check`.
//! Cross targets are linted and built (`cargo test --no-run`); the host target
//! is fully tested.

use std::process::Command;

const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-gnu",
    "x86_64-apple-darwin",
];

fn host_target() -> &'static str {
    if cfg!(target_os = "windows") {
        "x86_64-pc-windows-gnu"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

fn cargo(args: &[&str]) {
    let status = Command::new("cargo")
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to spawn cargo: {error}"));
    if !status.success() {
        eprintln!("command failed: cargo {}", args.join(" "));
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn main() {
    cargo(&["fmt", "--all", "--check"]);

    let host = host_target();
    for &target in TARGETS {
        cargo(&[
            "clippy",
            "--target",
            target,
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]);

        if target == host {
            cargo(&["test", "--target", target]);
        } else {
            cargo(&["test", "--target", target, "--no-run"]);
        }
    }
}
