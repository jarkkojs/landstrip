// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::error::Error as StdError;
use std::fmt;
use std::io;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Error)]
pub(crate) enum Error {
    #[error("{0}")]
    Message(String),

    #[error("{0}")]
    Usage(String),

    #[error("{context}")]
    Context {
        context: String,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Message(_) | Self::Context { .. } | Self::Io(_) | Self::Json(_) => 1,
        }
    }

    pub(crate) fn with_source(
        context: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(source),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self}")?;

        let mut source = self.source();
        while let Some(error) = source {
            write!(formatter, ": {error}")?;
            source = error.source();
        }

        Ok(())
    }
}
