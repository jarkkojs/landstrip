// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod engine;
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    path = "fallback.rs"
)]
mod platform;

use crate::cli::{Cli, parse_cli};
use crate::config::load_settings;
use crate::engine::policy::resolve_policy;
use crate::engine::trap_fd::TrapFd;
use anyhow::Result;
use std::process;

fn main() {
    let cli = parse_cli().unwrap_or_else(|error| {
        eprintln!("{error}");
        process::exit(2);
    });

    if let Err(error) = run_with_cli(&cli) {
        log::error!("{error:#}");
        process::exit(1);
    }
}

fn run_with_cli(cli: &Cli) -> Result<()> {
    let default_filter = if cli.debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();

    let cwd = std::env::current_dir()?;

    log::debug!("cli: cwd: {}", cwd.display());
    let settings = load_settings(&cli.policy_paths, cli.format)?;
    let policy = resolve_policy(
        &settings.filesystem,
        &settings.network,
        &settings.windows,
        &cwd,
    )?;

    let trap_fd = TrapFd::from_fd(cli.trap_fd);

    platform::execute(&policy, &cli.tool, &cli.tool_args, &trap_fd)
}
