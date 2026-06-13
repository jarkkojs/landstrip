// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor for landstrip error response blocks.

use std::path::Path;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ErrorFd {
    fd: Option<i32>,
}

impl ErrorFd {
    pub(crate) fn from_fd(fd: Option<i32>) -> Self {
        Self { fd }
    }

    pub(crate) fn is_enabled(self) -> bool {
        self.fd.is_some()
    }

    pub(crate) fn close(self) {
        let Some(fd) = self.fd else {
            return;
        };
        close_error_fd(fd);
    }

    pub(crate) fn emit_filesystem_denial(self, operation: &str, path: &Path, mechanism: &str) {
        let Some(fd) = self.fd else {
            return;
        };

        let response = format!(
            "reason: AccessDenied\ntype: filesystem\nfile: {}\noperation: {operation}\nmechanism: {mechanism}\n\n",
            path.display()
        );
        write_error_line(fd, response.as_bytes());
    }
}

#[cfg(unix)]
fn write_error_line(fd: i32, line: &[u8]) {
    let mut remaining = line;
    while !remaining.is_empty() {
        // SAFETY: write(2) copies bytes from the live slice pointer.
        let written = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if written == 0 {
            return;
        }
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log::debug!(
                "error fd write fd={fd} errno={}",
                error.raw_os_error().unwrap_or(0)
            );
            return;
        }

        let Ok(written) = usize::try_from(written) else {
            return;
        };
        remaining = &remaining[written..];
    }
}

#[cfg(unix)]
fn close_error_fd(fd: i32) {
    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        log::debug!(
            "error fd close fd={fd} errno={}",
            error.raw_os_error().unwrap_or(0)
        );
    }
}

#[cfg(not(unix))]
fn write_error_line(_fd: i32, _line: &[u8]) {}

#[cfg(not(unix))]
fn close_error_fd(_fd: i32) {}
