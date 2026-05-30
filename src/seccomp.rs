// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::landlock::enforce_access_policy;
use crate::paths::normalize_path;
use crate::policy::AccessPolicy;
use libseccomp::{
    ScmpAction, ScmpFilterContext, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags, ScmpSyscall,
    ScmpVersion, get_api as seccomp_api_level, notify_id_valid,
};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const NOTIFY_API: u32 = 6;
const POLL_MS: u16 = 100;

type SysResult<T> = std::result::Result<T, i32>;

#[allow(clippy::too_many_lines)]
pub(crate) fn run_local_bind(
    policy: &AccessPolicy,
    command: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    let api_level = seccomp_api_level();
    let version =
        ScmpVersion::current().map_err(|source| Error::with_source("seccomp: version", source))?;

    if api_level < NOTIFY_API {
        return Err(Error::message(format!(
            "seccomp: user notification requires libseccomp API level \
             {NOTIFY_API} or newer; current level is {api_level} \
             with libseccomp {version}"
        )));
    }

    let _filter = bind_filter()?;
    let (parent, child_sock) =
        UnixStream::pair().map_err(|source| Error::with_source("seccomp: socketpair", source))?;

    // SAFETY: landstrip forks before spawning threads; the child either execs the target or exits.
    match unsafe { fork() }.map_err(|source| Error::with_source("seccomp: fork", source))? {
        ForkResult::Child => {
            drop(parent);

            let result = (|| -> Result<()> {
                enforce_access_policy(policy)?;

                let filter = bind_filter()?;
                filter
                    .load()
                    .map_err(|source| Error::with_source("seccomp: load", source))?;
                let notify = filter
                    .get_notify_fd()
                    .map_err(|source| Error::with_source("seccomp: notify fd", source))?;

                // SAFETY: notify is borrowed only for the duration of fcntl(2).
                let notify_fd = unsafe { BorrowedFd::borrow_raw(notify) };
                let notify = fcntl(notify_fd, FcntlArg::F_DUPFD_CLOEXEC(0))
                    .map_err(|source| Error::with_source("seccomp: duplicate notify fd", source))?;
                // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
                let notify = unsafe { OwnedFd::from_raw_fd(notify) };

                send_fd(&child_sock, notify.as_raw_fd())
                    .map_err(|source| Error::with_source("seccomp: send notify fd", source))?;
                drop(child_sock);

                let error = Command::new(command).args(args).exec();
                Err(Error::with_source(
                    format!("exec: {}", command.to_string_lossy()),
                    error,
                ))
            })();

            if let Err(error) = result {
                eprintln!("landstrip child setup failed: {error:?}");
            }

            // SAFETY: _exit terminates the child without running duplicated parent cleanup.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let notify = recv_fd(&parent)
                .map_err(|source| Error::with_source("seccomp: receive notify fd", source))?;
            drop(parent);
            let notify = notify.as_raw_fd();

            loop {
                loop {
                    match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) => break,
                        Ok(status) => return Ok(ExitCode::from(status).into()),
                        Err(Errno::EINTR) => continue,
                        Err(source) => return Err(Error::with_source("seccomp: wait", source)),
                    }
                }

                // SAFETY: notify is the live seccomp notification fd owned by the parent.
                let borrowed = unsafe { BorrowedFd::borrow_raw(notify) };
                let mut poll_fd = [PollFd::new(borrowed, PollFlags::POLLIN)];
                let revents = loop {
                    match poll(&mut poll_fd, POLL_MS) {
                        Ok(0) => break PollFlags::empty(),
                        Ok(_) => break poll_fd[0].revents().unwrap_or_else(PollFlags::empty),
                        Err(Errno::EINTR) => continue,
                        Err(source) => return Err(Error::with_source("seccomp: poll", source)),
                    }
                };

                if revents.is_empty() {
                    continue;
                }

                if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                {
                    loop {
                        match waitpid(child, None) {
                            Ok(status) => return Ok(ExitCode::from(status).into()),
                            Err(Errno::EINTR) => continue,
                            Err(source) => return Err(Error::with_source("seccomp: wait", source)),
                        }
                    }
                }

                let request = ScmpNotifReq::receive(notify).map_err(|source| {
                    Error::with_source("seccomp: receive notification", source)
                })?;
                let result = (|| -> SysResult<i64> {
                    let fd = request.data.args[0] as RawFd;
                    let remote_addr =
                        usize::try_from(request.data.args[1]).map_err(|_| libc::EFAULT)?;
                    let addr_len =
                        usize::try_from(request.data.args[2]).map_err(|_| libc::EINVAL)?;
                    let pid = Pid::from_raw(i32::try_from(request.pid).map_err(|_| libc::EINVAL)?);

                    if addr_len > mem::size_of::<libc::sockaddr_storage>() {
                        return Err(libc::EINVAL);
                    }

                    let mut addr = vec![0_u8; addr_len];
                    let mut local = [IoSliceMut::new(&mut addr)];
                    let remote = [RemoteIoVec {
                        base: remote_addr,
                        len: addr_len,
                    }];
                    if process_vm_readv(pid, &mut local, &remote).map_err(|error| error as i32)?
                        != addr_len
                    {
                        return Err(libc::EFAULT);
                    }

                    // SAFETY: pidfd_open copies scalar arguments and returns a new fd on success.
                    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
                    if pidfd < 0 {
                        return Err(Errno::last_raw());
                    }
                    // SAFETY: pidfd_open returned a new owned descriptor.
                    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };

                    // SAFETY: pidfd_getfd copies scalar arguments and returns a duplicated fd.
                    let sock =
                        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
                    if sock < 0 {
                        return Err(Errno::last_raw());
                    }
                    // SAFETY: pidfd_getfd returned a new owned descriptor.
                    let sock = unsafe { OwnedFd::from_raw_fd(sock as RawFd) };

                    let domain = sockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_DOMAIN)?;
                    let ty = sockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TYPE)?;
                    let proto = sockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PROTOCOL)?;

                    if matches!(domain, libc::AF_INET | libc::AF_INET6)
                        && ty == libc::SOCK_STREAM
                        && proto == libc::IPPROTO_TCP
                    {
                        if addr.len() >= mem::size_of::<libc::sa_family_t>() {
                            let family =
                                i32::from(libc::sa_family_t::from_ne_bytes([addr[0], addr[1]]));
                            if domain == libc::AF_INET && family == libc::AF_INET {
                                if addr.len() >= mem::size_of::<libc::sockaddr_in>() {
                                    let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
                                    if !ip.is_loopback() {
                                        return Err(libc::EACCES);
                                    }
                                }
                            } else if domain == libc::AF_INET6
                                && family == libc::AF_INET6
                                && addr.len() >= mem::size_of::<libc::sockaddr_in6>()
                            {
                                let ip = Ipv6Addr::from(
                                    <[u8; 16]>::try_from(&addr[8..24]).map_err(|_| libc::EINVAL)?,
                                );
                                if !ip.is_loopback() {
                                    return Err(libc::EACCES);
                                }
                            }
                        }
                    } else if domain == libc::AF_UNIX {
                        let sun_path = mem::size_of::<libc::sa_family_t>();
                        if addr.len() > sun_path && addr[sun_path] != 0 {
                            let path = &addr[sun_path..];
                            let end = path
                                .iter()
                                .position(|byte| *byte == 0)
                                .unwrap_or(path.len());
                            if end > 0 {
                                let path = Path::new(OsStr::from_bytes(&path[..end]));
                                let target = if path.is_absolute() {
                                    create_path(path)
                                } else {
                                    let cwd = fs::read_link(format!("/proc/{}/cwd", pid.as_raw()))
                                        .map_err(|error| {
                                            error.raw_os_error().unwrap_or(libc::EIO)
                                        })?;
                                    create_path(&cwd.join(path))
                                };

                                if !policy
                                    .write_roots
                                    .iter()
                                    .any(|root| target == *root || target.starts_with(root))
                                {
                                    return Err(libc::EACCES);
                                }

                                if !path.is_absolute() {
                                    let path = target.as_os_str().as_bytes();
                                    let max_path = mem::size_of::<libc::sockaddr_un>() - sun_path;
                                    if path.len() + 1 > max_path {
                                        return Err(libc::ENAMETOOLONG);
                                    }

                                    let mut rewritten = vec![0_u8; sun_path + path.len() + 1];
                                    rewritten[..sun_path].copy_from_slice(&addr[..sun_path]);
                                    rewritten[sun_path..sun_path + path.len()]
                                        .copy_from_slice(path);
                                    addr = rewritten;
                                }
                            }
                        }
                    }

                    // SAFETY: sockaddr_storage is plain old data and zero is a valid byte pattern.
                    let mut storage = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
                    // SAFETY: storage is large enough because addr_len is capped above.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            addr.as_ptr(),
                            ptr::addr_of_mut!(storage).cast::<u8>(),
                            addr.len(),
                        );
                    }
                    let addr_len =
                        libc::socklen_t::try_from(addr.len()).map_err(|_| libc::EINVAL)?;

                    // SAFETY: storage contains the copied target sockaddr bytes and is aligned.
                    let rc = unsafe {
                        libc::bind(
                            sock.as_raw_fd(),
                            ptr::addr_of!(storage).cast::<libc::sockaddr>(),
                            addr_len,
                        )
                    };
                    if rc < 0 {
                        Err(Errno::last_raw())
                    } else {
                        Ok(i64::from(rc))
                    }
                })();
                let response = match result {
                    Ok(value) => {
                        ScmpNotifResp::new_val(request.id, value, ScmpNotifRespFlags::empty())
                    }
                    Err(errno) => ScmpNotifResp::new_error(
                        request.id,
                        -errno.abs(),
                        ScmpNotifRespFlags::empty(),
                    ),
                };

                notify_id_valid(notify, request.id)
                    .map_err(|source| Error::with_source("seccomp: stale notification", source))?;
                if let Err(source) = response.respond(notify) {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => break,
                            Ok(status) => return Ok(ExitCode::from(status).into()),
                            Err(Errno::EINTR) => continue,
                            Err(wait_error) => {
                                return Err(Error::with_source("seccomp: wait", wait_error));
                            }
                        }
                    }

                    return Err(Error::with_source("seccomp: respond", source));
                }
            }
        }
    }
}

fn bind_filter() -> Result<ScmpFilterContext> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|source| Error::with_source("seccomp: filter", source))?;
    let bind = ScmpSyscall::from_name("bind")
        .map_err(|source| Error::with_source("seccomp: syscall bind", source))?;

    filter
        .add_rule(ScmpAction::Notify, bind)
        .map_err(|source| Error::with_source("seccomp: rule bind", source))?;

    Ok(filter)
}

fn create_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("/"));
    let parent = normalize_path(parent);

    path.file_name()
        .map_or(parent.clone(), |name| parent.join(name))
}

fn sockopt(fd: RawFd, level: libc::c_int, name: libc::c_int) -> SysResult<i32> {
    let mut value = 0;
    let mut len = libc::socklen_t::try_from(mem::size_of_val(&value)).map_err(|_| libc::EINVAL)?;

    // SAFETY: value and len point to initialized storage for getsockopt(2) to update.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            ptr::addr_of_mut!(value).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc < 0 {
        Err(Errno::last_raw())
    } else {
        Ok(value)
    }
}

fn send_fd(socket: &UnixStream, fd: RawFd) -> io::Result<()> {
    let byte = [0_u8];
    let iov = [IoSlice::new(&byte)];
    let fds = [fd];

    sendmsg::<()>(
        socket.as_raw_fd(),
        &iov,
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .map(|_| ())
    .map_err(|error| io::Error::from_raw_os_error(error as i32))
}

fn recv_fd(socket: &UnixStream) -> io::Result<OwnedFd> {
    let mut byte = [0_u8];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;

    if message.bytes == 0 {
        return Err(io::Error::from_raw_os_error(libc::ECONNRESET));
    }

    for control in message
        .cmsgs()
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?
    {
        if let ControlMessageOwned::ScmRights(fds) = control {
            let Some(fd) = fds.first().copied() else {
                continue;
            };
            // SAFETY: SCM_RIGHTS transfers ownership of the received descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    Err(io::Error::from_raw_os_error(libc::EBADMSG))
}

struct ExitCode(i32);

impl From<WaitStatus> for ExitCode {
    fn from(status: WaitStatus) -> Self {
        Self(match status {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
            _ => 1,
        })
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code.0
    }
}
