// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod config;
mod error;
mod fd;
mod landlock;
mod paths;
mod policy;
mod seccomp;
mod traversal;

use crate::cli::parse_cli;
use crate::config::load_settings;
use crate::error::{Error, Result};
use crate::landlock::enforce_access_policy;
use crate::policy::{UnixSocketAccess, lower_sandbox_policy};
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

fn main() {
    if let Err(error) = run() {
        let exit_code = match error {
            Error::Usage(_) => 2,
            _ => 1,
        };

        eprintln!("{error:?}");
        process::exit(exit_code);
    }
}

fn run() -> Result<()> {
    let cli = parse_cli()?;
    init_logger(cli.debug);

    log::debug!("policy: base {}", cli.policy_base.display());
    let settings = load_settings(&cli.policy_paths)?;
    let policy = lower_sandbox_policy(&settings.filesystem, &settings.network, &cli.policy_base)?;

    if policy.network_access.local_tcp_bind
        || !policy.network_access.connect_tcp_ports.is_empty()
        || needs_unix_socket_broker(&policy.network_access.unix_socket_access)
    {
        let status = seccomp::run_network_broker(&policy, &cli.command, &cli.command_args)?;
        process::exit(status);
    }

    enforce_access_policy(&policy)?;
    {
        let filter = seccomp::network_filter(seccomp::NetworkFilter {
            notify_bind: false,
            notify_connect: false,
            unix_sockets: unix_socket_filter(&policy.network_access.unix_socket_access),
        })?;
        filter.load().map_err(Error::Seccomp)?;
    }
    fd::close_inherited_fds();
    let error = Command::new(&cli.command).args(&cli.command_args).exec();
    Err(Error::Exec {
        command: cli.command,
        source: error,
    })
}

fn init_logger(debug: bool) {
    let default_filter = if debug { "debug" } else { "warn" };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp(None)
        .init();
}

fn needs_unix_socket_broker(access: &UnixSocketAccess) -> bool {
    matches!(access, UnixSocketAccess::AllowPaths(paths) if !paths.is_empty())
}

fn unix_socket_filter(access: &UnixSocketAccess) -> seccomp::UnixSocketFilter {
    match access {
        UnixSocketAccess::Unrestricted => seccomp::UnixSocketFilter::Unrestricted,
        UnixSocketAccess::AllowPaths(paths) if paths.is_empty() => {
            seccomp::UnixSocketFilter::DenyAll
        }
        UnixSocketAccess::AllowPaths(_) => seccomp::UnixSocketFilter::PathMediated,
    }
}
