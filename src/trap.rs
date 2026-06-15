// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use strum_macros::Display;

pub(crate) type Result<T> = std::result::Result<T, Trap>;
#[derive(Debug)]
pub(crate) struct Cause(Box<dyn StdError + Send + Sync + 'static>);

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for Cause {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Display, Serialize)]
pub(crate) enum TrapCode {
    AccessDenied,
    Usage,
    LaunchFailed,
    Internal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub(crate) enum TrapCategory {
    Filesystem,
    Network,
    Platform,
    Launch,
    Encoding,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub(crate) enum TrapOperation {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Serialize)]
pub(crate) struct Trap {
    #[serde(rename = "reason")]
    pub(crate) code: TrapCode,

    #[serde(rename = "source")]
    pub(crate) message: String,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub(crate) category: Option<TrapCategory>,

    #[serde(rename = "file", skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation: Option<TrapOperation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) program: Option<OsString>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cause: Option<Cause>,
}

impl Trap {
    pub(crate) fn new(code: TrapCode) -> Self {
        Self {
            code,
            message: String::new(),
            category: None,
            path: None,
            operation: None,
            program: None,
            detail: None,
            cause: None,
        }
    }

    pub(crate) fn emit(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap_or_default());
    }

    pub(crate) fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub(crate) fn with_category(mut self, category: TrapCategory) -> Self {
        self.category = Some(category);
        self
    }

    pub(crate) fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    pub(crate) fn with_operation(mut self, operation: TrapOperation) -> Self {
        self.operation = Some(operation);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_program(mut self, program: OsString) -> Self {
        self.program = Some(program);
        self
    }

    pub(crate) fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), value.into());
        self
    }

    pub(crate) fn tool_exec(program: Option<OsString>, error: io::Error) -> Self {
        let code = if error.kind() == io::ErrorKind::NotFound {
            TrapCode::LaunchFailed
        } else {
            TrapCode::Internal
        };
        let category = if error.kind() == io::ErrorKind::NotFound {
            Some(TrapCategory::Launch)
        } else {
            Some(TrapCategory::Encoding)
        };
        Self {
            program,
            message: error.to_string(),
            category,
            cause: Some(Cause(Box::new(error))),
            ..Self::new(code)
        }
    }

    pub(crate) fn policy_stdin_source(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            message: source.to_string(),
            cause: Some(Cause(Box::new(source))),
            ..Self::new(TrapCode::Internal)
        }
    }

    pub(crate) fn policy_file_source(
        path: PathBuf,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            path: Some(path),
            message: source.to_string(),
            cause: Some(Cause(Box::new(source))),
            ..Self::new(TrapCode::Internal)
        }
    }
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let TrapCode::Usage = self.code {
            if !self.message.is_empty() {
                return f.write_str(&self.message);
            }
            return f.write_str("landstrip: usage error");
        }
        write!(f, "{}", self.code)?;
        if let Some(ref path) = self.path {
            write!(f, ": {}", path.display())?;
        } else if let Some(ref program) = self.program {
            write!(f, ": {}", program.to_string_lossy())?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

impl StdError for Trap {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| &*cause.0 as &(dyn StdError + 'static))
    }
}

impl From<io::Error> for Trap {
    fn from(error: io::Error) -> Self {
        let message = error.to_string();
        Self {
            message,
            cause: Some(Cause(Box::new(error))),
            ..Self::new(TrapCode::Internal)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PolicyPort {
    HttpProxyPolicy,
    SocksProxyPolicy,
}

impl fmt::Display for PolicyPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpProxyPolicy => f.write_str("http_proxy_port"),
            Self::SocksProxyPolicy => f.write_str("socks_proxy_port"),
        }
    }
}
