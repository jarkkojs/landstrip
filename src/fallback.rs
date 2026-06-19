// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Fallback platform implementation for unsupported platforms.
//!
//! Returns an error to communicate that the current operating system is not yet
//! supported by landstrip.

use crate::policy::AccessPolicy;
use crate::trap_fd::TrapFd;
use anyhow::{Result, anyhow};
use std::ffi::{OsStr, OsString};

pub(crate) fn execute(
    _policy: &AccessPolicy,
    _tool: &OsStr,
    _args: &[OsString],
    _trap_fd: &TrapFd,
) -> Result<()> {
    Err(anyhow!("unsupported platform"))
}
