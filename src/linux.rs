// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Linux sandbox backend using Landlock and seccomp.

use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::fd::close_inherited_fds;
use crate::landlock::enforce_access_policy;
use crate::policy::AccessPolicy;
use crate::seccomp::{self, NetworkFilter};
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

pub(crate) struct LinuxBackend;

impl Backend for LinuxBackend {
    fn execute(&self, policy: &AccessPolicy, command: &OsStr, args: &[OsString]) -> Result<()> {
        if policy.network_access.local_tcp_bind
            || !policy.network_access.connect_tcp_ports.is_empty()
            || seccomp::needs_unix_socket_broker(&policy.network_access.unix_socket_access)
        {
            let status = seccomp::run_network_broker(policy, command, args)?;
            process::exit(status);
        }

        enforce_access_policy(policy)?;
        {
            let filter = seccomp::network_filter(NetworkFilter {
                notify_bind: false,
                notify_connect: false,
                unix_sockets: seccomp::unix_socket_filter(
                    &policy.network_access.unix_socket_access,
                ),
            })?;
            filter.load().map_err(Error::Seccomp)?;
        }
        close_inherited_fds();
        let error = Command::new(command).args(args).exec();
        Err(Error::Exec {
            command: command.to_os_string(),
            source: error,
        })
    }
}
