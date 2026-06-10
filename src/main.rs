// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod error;
mod paths;
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    path = "fallback.rs"
)]
mod platform;
mod policy;
mod traversal;

use crate::cli::{Cli, parse_cli};
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::policy::resolve_policy;
use std::process;

fn main() {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(error) => {
            print_error_response(&error);
            process::exit(if matches!(error, Error::Usage(_)) {
                2
            } else {
                1
            });
        }
    };

    if let Err(error) = run_with_cli(&cli) {
        if let Error::Usage(_) = &error {
            eprintln!("{error}");
            process::exit(2);
        }
        print_error_response(&error);
        process::exit(1);
    }
}

fn print_error_response(error: &Error) {
    let Some(response) = error.response() else {
        return;
    };

    eprintln!("category: {}", response.category);
    if let Some(file) = &response.file {
        eprintln!("file: {file}");
    }
    if let Some(program) = &response.program {
        eprintln!("program: {program}");
    }
    if let Some(e_type) = response.r#type {
        eprintln!("type: {e_type}");
    }
    eprintln!("message: {}", response.message);
}

fn run_with_cli(cli: &Cli) -> Result<()> {
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir()?;

    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths, cli.format)?;
    let policy = resolve_policy(&settings.filesystem, &settings.network, &cwd)?;

    platform::execute(&policy, &cli.tool, &cli.tool_args)?;

    Ok(())
}
