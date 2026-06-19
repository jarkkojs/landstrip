// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use std::fs;
use std::path::{Component, Path, PathBuf};

pub(crate) fn normalize_roots(paths: &mut Vec<PathBuf>) {
    for path in paths.iter_mut() {
        *path = normalize_path(path);
    }

    paths.sort_unstable();
    paths.dedup();
}

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
    if cfg!(not(target_os = "macos")) {
        if let Ok(canonical) = fs::canonicalize(path) {
            return canonical;
        }
    }

    normalize_path_lexically(path)
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
