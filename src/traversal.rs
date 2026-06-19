// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::paths::normalize_roots;
use crate::policy::AccessPolicyError;
use anyhow::Result;
use rayon::prelude::*;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_TRAVERSAL_DEPTH: u32 = 40;

pub(crate) fn subtract_denied_roots(
    mut allowed: Vec<PathBuf>,
    denied: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    normalize_roots(&mut allowed);
    let mut denied = denied.to_vec();
    normalize_roots(&mut denied);
    let mut roots: Vec<PathBuf> = allowed
        .par_iter()
        .map(|root| scan_allowed_root(root, &denied, true, 0))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    normalize_roots(&mut roots);

    Ok(roots)
}

fn scan_allowed_root(
    root: &Path,
    denied: &[PathBuf],
    is_explicit_root: bool,
    depth: u32,
) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    let mut stack = vec![(root.to_path_buf(), is_explicit_root, depth)];

    while let Some((current, is_explicit, depth)) = stack.pop() {
        if depth >= MAX_TRAVERSAL_DEPTH {
            return Err(AccessPolicyError::TraversalDepth.into());
        }

        if denied
            .iter()
            .any(|denied_root| current == *denied_root || current.starts_with(denied_root))
        {
            continue;
        }

        let has_denied_descendant = denied
            .iter()
            .any(|denied_root| denied_root.starts_with(&current));

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::PermissionDenied =>
            {
                results.push(current);
                continue;
            }
            Err(source) => return Err(source.into()),
        };
        let file_type = metadata.file_type();

        if file_type.is_symlink() && !is_explicit {
            continue;
        }
        if !has_denied_descendant || !file_type.is_dir() {
            results.push(current);
            continue;
        }

        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                results.push(current);
                continue;
            }
            Err(source) => return Err(source.into()),
        };
        for entry in entries {
            let entry = entry?;
            let child = entry.path();
            stack.push((child, false, depth + 1));
        }
    }

    Ok(results)
}
