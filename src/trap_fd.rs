// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Separate file descriptor or file path for landstrip trap response blocks.

use crate::trap::Trap;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub(crate) struct TrapFd {
    // A raw descriptor is a unix-only `--trap-fd` concept; other platforms use the file sink.
    #[cfg_attr(not(unix), allow(dead_code))]
    fd: Option<i32>,
    file: Option<PathBuf>,
}

impl TrapFd {
    pub(crate) fn from_fd(fd: Option<i32>) -> Self {
        Self { fd, file: None }
    }

    pub(crate) fn from_file(path: PathBuf) -> Self {
        Self {
            fd: None,
            file: Some(path),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_enabled(&self) -> bool {
        self.fd.is_some() || self.file.is_some()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn is_socket(&self) -> bool {
        self.fd.is_some_and(|fd| {
            crate::platform::fd::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE).is_ok()
        })
    }

    #[cfg(unix)]
    pub(crate) fn close(&self) {
        if let Some(fd) = self.fd {
            close_trap_fd(fd);
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fd(&self) -> Option<i32> {
        self.fd
    }

    pub(crate) fn write(&self, trap: &Trap) {
        let Ok(line) = serde_json::to_string(trap) else {
            return;
        };
        let line = format!("{line}\n");

        #[cfg(unix)]
        if let Some(fd) = self.fd {
            write_trap_fd(fd, line.as_bytes());
            return;
        }

        if let Some(ref path) = self.file {
            write_trap_file(path, line.as_bytes());
        }
    }
}

#[cfg(unix)]
fn write_trap_fd(fd: i32, line: &[u8]) {
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
                "trap fd write fd={fd} errno={}",
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

fn write_trap_file(path: &PathBuf, line: &[u8]) {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);
    match opts.open(path) {
        Ok(mut file) => {
            if let Err(error) = file.write_all(line) {
                log::debug!("trap file write path={} err={error}", path.display());
            }
        }
        Err(error) => {
            log::debug!("trap file open path={} err={error}", path.display());
        }
    }
}

#[cfg(unix)]
fn close_trap_fd(fd: i32) {
    // SAFETY: close(2) copies the scalar file descriptor argument.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        log::debug!(
            "trap fd close fd={fd} errno={}",
            error.raw_os_error().unwrap_or(0)
        );
    }
}
