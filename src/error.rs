// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::{Serialize, Serializer};
use std::fmt;
use std::io;

/// A landstrip error identified by a stable, machine-routable code.
///
/// `Display` and `Serialize` both render the `SCREAMING_SNAKE_CASE` code.
/// [`Error::IoFailed`] carries the underlying [`io::Error`] as its source, leaving it
/// to the caller to log the detail, format it, or route the code.
#[derive(Debug, strum_macros::IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Error {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    FilesystemDenied,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NetworkDenied,
    IoFailed(io::Error),
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    IntegerTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.into())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoFailed(error) => Some(error),
            Self::FilesystemDenied | Self::NetworkDenied | Self::IntegerTooLarge => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::IoFailed(error)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::errno::Errno> for Error {
    fn from(errno: nix::errno::Errno) -> Self {
        Self::IoFailed(io::Error::from_raw_os_error(errno as i32))
    }
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.into())
    }
}
