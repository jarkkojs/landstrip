// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! OS-specific sandbox execution backends.

use crate::error::Result;
use crate::policy::AccessPolicy;
use std::ffi::{OsStr, OsString};

/// Trait for platform-specific sandbox backends.
pub(crate) trait Backend {
    /// Execute `command` with `args` under the given access policy.
    ///
    /// On success this function replaces the current process image and
    /// therefore never returns. On error a [`Result`] is returned.
    fn execute(&self, policy: &AccessPolicy, command: &OsStr, args: &[OsString]) -> Result<()>;
}

/// Compile-time platform backend selection.
#[cfg(target_os = "linux")]
pub(crate) use crate::linux::LinuxBackend as PlatformBackend;

#[cfg(target_os = "macos")]
pub(crate) use crate::apple::SeatbeltBackend as PlatformBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use crate::fallback::FallbackBackend as PlatformBackend;
