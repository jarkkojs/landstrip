// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Landlock enforcement for lowered filesystem and TCP port rules.
//!
//! Filesystem rules grant access to objects opened while creating the ruleset.
//! This gives deny traversal snapshot semantics: a removed and recreated path is
//! a new object unless an allowed ancestor covers it.

use crate::error::{Error, Result};
use crate::policy::{AccessPolicy, ReadAccess};
use landlock::{
    ABI, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};
use std::path::{Path, PathBuf};

pub(crate) fn enforce_access_policy(policy: &AccessPolicy) -> Result<()> {
    let write_access = AccessFs::from_write(ABI::V7);
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let handled_access = match &policy.read_access {
        ReadAccess::Unrestricted => write_access,
        ReadAccess::AllowRoots(_) => write_access | read_access,
    };

    let ruleset = Ruleset::default().handle_access(handled_access)?;
    let mut ruleset = handle_network_access(ruleset, policy)?.create()?;

    ruleset = add_path_rules(ruleset, &policy.write_roots, write_access, "write")?;

    if let ReadAccess::AllowRoots(read_roots) = &policy.read_access {
        ruleset = add_path_rules(ruleset, read_roots, read_access, "read")?;
    }

    ruleset = add_network_rules(ruleset, policy)?;

    let status = ruleset.restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => Err(Error::LandlockPartial),
        RulesetStatus::NotEnforced => Err(Error::LandlockNone),
    }
}

fn handle_network_access(ruleset: Ruleset, policy: &AccessPolicy) -> Result<Ruleset> {
    let mut access = BitFlags::<AccessNet>::EMPTY;

    if policy.network_access.restrict_connect_tcp {
        access |= AccessNet::ConnectTcp;
    }

    if policy.network_access.restrict_bind_tcp {
        access |= AccessNet::BindTcp;
    }

    if access.is_empty() {
        return Ok(ruleset);
    }

    ruleset
        .handle_access(access)
        .map_err(Error::LandlockRuleset)
}

fn add_path_rules(
    mut ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    _label: &str,
) -> Result<RulesetCreated> {
    for path in paths {
        let fd = PathFd::new(path)?;
        let rule = PathBeneath::new(fd, access_for_path(path, access));
        ruleset = ruleset.add_rule(rule)?;
    }

    Ok(ruleset)
}

fn add_network_rules(mut ruleset: RulesetCreated, policy: &AccessPolicy) -> Result<RulesetCreated> {
    if !policy.network_access.restrict_connect_tcp {
        return Ok(ruleset);
    }

    for port in &policy.network_access.connect_tcp_ports {
        let rule = NetPort::new(*port, AccessNet::ConnectTcp);
        ruleset = ruleset.add_rule(rule)?;
    }

    Ok(ruleset)
}

fn access_for_path(path: &Path, access: BitFlags<AccessFs>) -> BitFlags<AccessFs> {
    if path.is_dir() {
        access
    } else {
        access & AccessFs::from_file(ABI::V7)
    }
}
