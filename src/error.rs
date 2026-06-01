// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::ffi::OsString;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum Error {
    AddressFamilyNotSupported,
    BadAddress,
    BadFileDescriptor,
    Exec {
        command: OsString,
        source: io::Error,
    },
    InvalidAddress,
    Io(io::Error),
    Json(serde_json::Error),
    LandlockNone,
    LandlockPartial,
    LandlockPathFd(landlock::PathFdError),
    LandlockRuleset(landlock::RulesetError),
    MissingFileDescriptor,
    NameTooLong,
    Nix(nix::errno::Errno),
    NotSupportedNotifyApi {
        required: u32,
        current: u32,
        version: String,
    },
    PeerClosed,
    PolicyDenied,
    PolicyDomainEmpty {
        list: DomainList,
        value: String,
    },
    PolicyDomainInvalidHost {
        list: DomainList,
        value: String,
    },
    PolicyDomainInvalidWildcard {
        list: DomainList,
        value: String,
    },
    PolicyDomainIpLiteral {
        list: DomainList,
        value: String,
    },
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
    PolicyPortEmpty(PolicyPort),
    PolicyPortOutOfRange(PolicyPort),
    PolicyPortParse {
        port: PolicyPort,
        source: ParseIntError,
    },
    PolicyTildeUserNotSupported,
    ProxyAuthorityHasUserinfo,
    ProxyAuthorityMissingHost,
    ProxyHttpHeaderTooLarge,
    ProxyIncompleteHttpRequest,
    ProxyInvalidAuthority,
    ProxyInvalidAuthorityHeader,
    ProxyInvalidHttpHeaderName,
    ProxyInvalidHttpHeaderValue,
    ProxyInvalidHttpMethod,
    ProxyInvalidHttpRequest,
    ProxyInvalidHttpResponse,
    ProxyInvalidHttpTarget,
    ProxyInvalidProxyUrlPath,
    ProxyInvalidSocksDomain,
    ProxyMissingAuthorityHeader,
    ProxyMissingHttpMethod,
    ProxyMissingHttpTarget,
    ProxyMissingHttpVersion,
    ProxyMissingProxyUrlHost,
    ProxyNotSupportedHttpVersion,
    ProxyNotSupportedProxyUrlScheme,
    ProxyNotSupportedSocksRequestVersion,
    ProxyNotSupportedSocksVersion,
    Seccomp(libseccomp::error::SeccompError),
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

impl From<nix::errno::Errno> for Error {
    fn from(source: nix::errno::Errno) -> Self {
        Self::Nix(source)
    }
}

impl From<libseccomp::error::SeccompError> for Error {
    fn from(source: libseccomp::error::SeccompError) -> Self {
        Self::Seccomp(source)
    }
}

impl From<landlock::RulesetError> for Error {
    fn from(source: landlock::RulesetError) -> Self {
        Self::LandlockRuleset(source)
    }
}

impl From<landlock::PathFdError> for Error {
    fn from(source: landlock::PathFdError) -> Self {
        Self::LandlockPathFd(source)
    }
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum PolicyPort {
    HttpProxyEnvironment,
    HttpProxyPolicy,
    SocksProxyEnvironment,
    SocksProxyPolicy,
}

#[derive(Clone, Copy, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum DomainList {
    Allowed,
    Denied,
}
