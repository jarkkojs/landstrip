#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

# Run formatting, clippy and tests across all supported targets.
# Cross targets are linted and built (cargo test --no-run); the host
# target is fully tested.

set -eu

# Tell the test runner not to re-enter the check suite from our cargo test runs.
export LANDSTRIP_RUNNER_NESTED=1

targets="x86_64-unknown-linux-gnu x86_64-pc-windows-gnu"
host_target=x86_64-unknown-linux-gnu

# Extra command a target needs to link; empty means the host linker suffices.
target_linker() {
    case $1 in
    x86_64-pc-windows-gnu) echo x86_64-w64-mingw32-dlltool ;;
    *) echo "" ;;
    esac
}

# Whether a target can be built here. Missing std or cross toolchain -> skip.
target_available() {
    if ! rustup target list --installed | grep -qx "$1"; then
        echo "warning: skipping $1: rustup target not installed" >&2
        return 1
    fi
    linker=$(target_linker "$1")
    if [ -n "$linker" ] && ! command -v "$linker" >/dev/null 2>&1; then
        echo "warning: skipping $1: missing toolchain ($linker)" >&2
        return 1
    fi
    return 0
}

cargo fmt --all --check

for target in $targets; do
    target_available "$target" || continue
    cargo clippy --target "$target" --all-targets -- -D warnings
    if [ "$target" = "$host_target" ]; then
        cargo test --target "$target"
    else
        cargo test --target "$target" --no-run
    fi
done
