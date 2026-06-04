// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use landlock::PathFdError;
#[cfg(target_os = "linux")]
use libseccomp::error::SeccompError;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum Error {
    #[cfg(target_os = "linux")]
    AddressFamilyNotSupported,
    #[cfg(target_os = "linux")]
    BadAddress,
    #[cfg(target_os = "linux")]
    BadFileDescriptor,
    Exec {
        command: OsString,
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    InvalidAddress,
    Io(io::Error),
    Json(serde_json::Error),
    #[cfg(target_os = "linux")]
    LandlockNone,
    #[cfg(target_os = "linux")]
    LandlockPartial,
    #[cfg(target_os = "linux")]
    LandlockPathFd(PathFdError),
    #[cfg(target_os = "linux")]
    LandlockRuleset(landlock::RulesetError),
    #[cfg(target_os = "linux")]
    MissingFileDescriptor,
    #[cfg(target_os = "linux")]
    NameTooLong,
    #[cfg(target_os = "linux")]
    Nix(nix::errno::Errno),
    #[cfg(target_os = "linux")]
    NotSupportedNotifyApi {
        required: u32,
        current: u32,
        version: String,
    },
    #[cfg(target_os = "linux")]
    PeerClosed,
    #[cfg(target_os = "linux")]
    PolicyDenied,
    PolicyFile {
        path: PathBuf,
        source: io::Error,
    },
    PolicyFileJson {
        path: PathBuf,
        source: serde_json::Error,
    },
    PolicyHomeUnavailable,
    PolicyPathEmpty,
    PolicyPortOutOfRange(PolicyPort),
    #[cfg(target_os = "linux")]
    Seccomp(SeccompError),
    #[cfg(target_os = "macos")]
    SeatbeltInit(String),
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    UnsupportedPlatform,
    Usage(String),
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::errno::Errno> for Error {
    fn from(source: nix::errno::Errno) -> Self {
        Self::Nix(source)
    }
}

#[cfg(target_os = "linux")]
impl From<SeccompError> for Error {
    fn from(source: SeccompError) -> Self {
        Self::Seccomp(source)
    }
}

#[cfg(target_os = "linux")]
impl From<landlock::RulesetError> for Error {
    fn from(source: landlock::RulesetError) -> Self {
        Self::LandlockRuleset(source)
    }
}

#[cfg(target_os = "linux")]
impl From<PathFdError> for Error {
    fn from(source: PathFdError) -> Self {
        Self::LandlockPathFd(source)
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}
