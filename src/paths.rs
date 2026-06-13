// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(not(target_os = "macos"))]
use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(not(target_os = "macos"))]
pub(crate) fn normalize_roots(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        *path = normalize_path(path);
    }

    paths.sort_unstable();
    paths.dedup();
}

#[cfg(target_os = "macos")]
pub(crate) fn normalize_roots_lexically(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        *path = normalize_path_lexically(path);
    }

    paths.sort_unstable();
    paths.dedup();
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => normalize_path_lexically(path),
    }
}

pub(crate) fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }

    normalized
}
