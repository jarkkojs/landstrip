#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
bin=${LANDSTRIP_BIN:-$repo_root/target/debug/landstrip}
nc_cmd=${NC:-nc}

test -x "$bin" || {
    echo "missing landstrip binary: $bin" >&2
    exit 1
}
command -v "$nc_cmd" >/dev/null 2>&1 || {
    echo "missing nc command" >&2
    exit 1
}
nc_path=$(command -v "$nc_cmd")
case $(uname -s) in
    Darwin) sandbox_shell=/bin/bash ;;
    *) sandbox_shell=/bin/sh ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/allowed" "$tmp/denied"

pass=0
fail=0
port_base=$((49152 + ($$ % 10000)))
test_seq=0

pass() {
    pass=$((pass + 1))
    printf 'PASS %s\n' "$1"
}

fail() {
    fail=$((fail + 1))
    printf 'FAIL %s -- %s\n' "$1" "$2"
}

expect_success() {
    name=$1
    shift
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        pass "$name"
    else
        fail "$name" "status=$status output=$output"
    fi
}

expect_failure() {
    name=$1
    shift
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        pass "$name"
    else
        fail "$name" "unexpected success output=$output"
    fi
}

write_policy() {
    fmt=$1; shift
    test_seq=$((test_seq + 1))
    file="$tmp/policy-$test_seq.json"
    printf "$fmt" "$@" >"$file"
    printf '%s\n' "$file"
}

test_ok() {
    name=$1
    policy=$2
    shift 2
    expect_success "$name" "$bin" -p "$policy" "$@"
}

test_fail() {
    name=$1
    policy=$2
    shift 2
    expect_failure "$name" "$bin" -p "$policy" "$@"
}

next_port() {
    port_base=$((port_base + 1))
    if [ "$port_base" -gt 60999 ]; then
        port_base=49152
    fi
    printf '%s\n' "$port_base"
}

expect_listener_denied() {
    name=$1
    policy=$2
    port=$(next_port)
    out=$tmp/listener-denied-$port.out

    set +e
    "$bin" -p "$policy" "$nc_path" -l 127.0.0.1 "$port" >"$out" 2>&1 &
    pid=$!
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null
        status=0
        running=1
    else
        wait "$pid"
        status=$?
        running=0
    fi
    set -e

    if [ "$running" -eq 0 ] && [ "$status" -ne 0 ]; then
        pass "$name"
    else
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "listener still running or exited successfully on port=$port output=$output"
    fi
}

expect_listener_allowed() {
    name=$1
    policy=$2
    port=$(next_port)
    out=$tmp/listener-allowed-$port.out

    "$bin" -p "$policy" "$nc_path" -l 127.0.0.1 "$port" >"$out" 2>&1 &
    pid=$!
    sleep 1

    if ! kill -0 "$pid" 2>/dev/null; then
        set +e
        wait "$pid"
        status=$?
        set -e
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "listener exited status=$status output=$output"
        return
    fi

    set +e
    "$nc_cmd" -z 127.0.0.1 "$port" >/dev/null 2>&1
    connect_status=$?
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    set -e

    if [ "$connect_status" -eq 0 ]; then
        pass "$name"
    else
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "connect failed status=$connect_status output=$output"
    fi
}

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"]}}' "$tmp")
test_ok "unrestricted read policy runs tool" "$policy" "$sandbox_shell" -c 'printf ok\\n'

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
test_ok "allowWrite permits configured root" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed"
test_fail "allowWrite denies other root" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/denied"

policy_yml=$tmp/policy-fs.yml
printf '%s\n' \
    'network:' \
    '  allowNetwork: true' \
    'filesystem:' \
    '  allowWrite: |' \
    "    $tmp/allowed" \
    '  denyRead: |' \
    '    /' \
    '  allowRead: |' \
    '    /' \
    >"$policy_yml"
expect_success "yml line policy permits configured root" \
    "$bin" --format yml -p "$policy_yml" "$sandbox_shell" -c ': > "$1/yml-ok.txt"; test -f "$1/yml-ok.txt"' _ "$tmp/allowed"
expect_failure "yml line policy denies other root" \
    "$bin" --format yml -p "$policy_yml" "$sandbox_shell" -c ': > "$1/yml-nope.txt"' _ "$tmp/denied"

expect_success "stdin yml policy runs tool" \
    "$sandbox_shell" -c 'printf "%s\n" "network:" "  allowNetwork: true" "filesystem:" "  denyRead: |" "    /" "  allowRead: |" "    /" | "$1" --format yml "$2" -c "printf ok\\n"' _ "$bin" "$sandbox_shell"

policy=$(write_policy '{"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_denied "default network denies TCP listener" "$policy"

policy=$(write_policy '{"network":{"allowLocalBinding":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_allowed "allowLocalBinding permits localhost listener" "$policy"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_allowed "allowNetwork permits localhost listener" "$policy"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":[""]}}')
test_fail "empty path is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

mkdir -p "$tmp/allowed/keep" "$tmp/allowed/sub"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyWrite":["%s/allowed/sub"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp" "$tmp")
test_ok "denyWrite permits sibling write" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed/keep"
test_fail "denyWrite denies subtree write" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/allowed/sub"

policy=$(write_policy '{"network":{"httpProxyPort":0},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
test_fail "httpProxyPort zero is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

printf 'SUMMARY pass=%s fail=%s tmp=%s\n' "$pass" "$fail" "$tmp"
[ "$fail" -eq 0 ]
