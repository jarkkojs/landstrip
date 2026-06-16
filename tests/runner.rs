// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use duct::{Expression, cmd};
use std::path::{Path, PathBuf};

const SUITES: &[u8] = include_bytes!("runner.txt");

#[test]
fn run_suites() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let landstrip = env!("CARGO_BIN_EXE_landstrip");
    let suites = std::str::from_utf8(SUITES).expect("runner.txt is not valid UTF-8");

    // check.sh/check.ps1 invoke cargo test themselves; skip the check suite when
    // we are already running inside one to avoid infinite recursion.
    let nested = std::env::var_os("LANDSTRIP_RUNNER_NESTED").is_some();

    for line in suites.lines() {
        let name = line.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        if nested && name == "check" {
            continue;
        }

        suite_command(&repo_root, name)
            .dir(&repo_root)
            .env("LANDSTRIP_BIN", landstrip)
            .run()
            .unwrap_or_else(|error| panic!("test suite '{name}' failed: {error}"));
    }
}

fn suite_command(repo_root: &Path, name: &str) -> Expression {
    let tests_dir = repo_root.join("tests");
    if cfg!(windows) {
        let script = tests_dir.join(format!("{name}.ps1"));
        cmd(
            "pwsh",
            [
                "-NoProfile".to_owned(),
                "-File".to_owned(),
                script.to_string_lossy().into_owned(),
            ],
        )
    } else {
        let script = tests_dir.join(format!("{name}.sh"));
        cmd("sh", [script.to_string_lossy().into_owned()])
    }
}
