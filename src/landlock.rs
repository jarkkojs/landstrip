// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, ReadAccess};
use landlock::{
    ABI, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};
use std::path::{Path, PathBuf};

pub(crate) fn enforce_access_policy(
    policy: &AccessPolicy,
    fail_if_unavailable: bool,
) -> Result<()> {
    let abi = ABI::V3;
    let write_access = AccessFs::from_write(abi);
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let handled_access = match &policy.read_access {
        ReadAccess::Unrestricted => write_access,
        ReadAccess::AllowRoots(_) => write_access | read_access,
    };

    let mut ruleset = Ruleset::default()
        .handle_access(handled_access)
        .map_err(|source| Error::with_source("landlock: rights", source))?
        .create()
        .map_err(|source| Error::with_source("landlock: ruleset", source))?;

    ruleset = add_path_rules(ruleset, &policy.write_roots, write_access, "write")?;

    if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        ruleset = add_path_rules(ruleset, read_roots, read_access, "read")?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|source| Error::with_source("landlock", source))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            handle_incomplete_sandbox("landlock: partially enforced", fail_if_unavailable)
        }
        RulesetStatus::NotEnforced => {
            handle_incomplete_sandbox("landlock: not enforced", fail_if_unavailable)
        }
    }
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    label: &str,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = PathFd::new(path).map_err(|source| {
            Error::with_source(format!("landlock: {label} root {}", path.display()), source)
        })?;
        let rule = PathBeneath::new(fd, access_for_path(path, access));
        ruleset = ruleset.add_rule(rule).map_err(|source| {
            Error::with_source(format!("landlock: {label} rule {}", path.display()), source)
        })?;
    }

    Ok(ruleset)
}

fn access_for_path(path: &Path, access: BitFlags<AccessFs>) -> BitFlags<AccessFs> {
    if path.is_dir() {
        access
    } else {
        access & AccessFs::from_file(ABI::V3)
    }
}

fn handle_incomplete_sandbox(message: &str, fail_if_unavailable: bool) -> Result<()> {
    if fail_if_unavailable {
        return Err(Error::message(message));
    }

    log::warn!("{message}");
    Ok(())
}
