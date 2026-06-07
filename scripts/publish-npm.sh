#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

die() {
	echo "$1" >&2
	exit 1
}

platform_package_dirs=(
	npm/darwin-arm64
	npm/darwin-x64
	npm/linux-x64
	npm/win32-x64
)

platform_package_targets=(
	aarch64-apple-darwin
	x86_64-apple-darwin
	x86_64-unknown-linux-gnu
	x86_64-pc-windows-msvc
)

platform_package_binaries=(
	landstrip
	landstrip
	landstrip
	landstrip.exe
)

usage() {
	cat <<'EOF'
usage: scripts/publish-npm.sh [npm-arg...]

Examples:
  scripts/publish-npm.sh --dry-run
  scripts/publish-npm.sh
EOF
}

validate_package_metadata() {
	node - "$@" <<'NODE'
const fs = require('node:fs');

const packageDirs = process.argv.slice(2);
const root = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const cargoToml = fs.readFileSync('Cargo.toml', 'utf8');
const cargoVersion = cargoToml.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];

if (!cargoVersion) {
  throw new Error('cannot find Cargo.toml package version');
}

if (root.version !== cargoVersion) {
  throw new Error(`package.json version ${root.version} does not match Cargo.toml ${cargoVersion}`);
}

for (const packageDir of packageDirs) {
  const data = JSON.parse(fs.readFileSync(`${packageDir}/package.json`, 'utf8'));

  if (data.version !== root.version) {
    throw new Error(`${packageDir}/package.json version ${data.version} does not match ${root.version}`);
  }

  if (root.optionalDependencies?.[data.name] !== root.version) {
    throw new Error(`package.json optional dependency ${data.name} does not match ${root.version}`);
  }
}
NODE
}

build_binaries() {
	local binary package_dir source_path target target_path index

	for index in "${!platform_package_dirs[@]}"; do
		package_dir="${platform_package_dirs[$index]}"
		target="${platform_package_targets[$index]}"
		binary="${platform_package_binaries[$index]}"
		source_path="target/$target/release/$binary"
		target_path="$package_dir/bin/$binary"

		if command -v rustup >/dev/null; then
			rustup target add "$target"
		fi

		cargo build --release --locked --target "$target"
		[[ -f "$source_path" ]] || die "missing built binary: $source_path"

		mkdir -p "$package_dir/bin"
		cp "$source_path" "$target_path"

		case "$target_path" in
		*.exe) ;;
		*) chmod 755 "$target_path" ;;
		esac
	done
}

validate_binaries() {
	local binary_path package_dir index

	for index in "$@"; do
		package_dir="${platform_package_dirs[$index]}"
		binary_path="$package_dir/bin/${platform_package_binaries[$index]}"

		[[ -f "$binary_path" ]] || die "missing binary: $binary_path"

		case "$binary_path" in
		*.exe) ;;
		*) [[ -x "$binary_path" ]] || die "binary is not executable: $binary_path" ;;
		esac
	done
}

publish_packages() {
	local package_dir

	for package_dir in "$@"; do
		npm publish "./$package_dir" "${publish_args[@]}"
	done
}

case "${1:-}" in
-h|--help)
	usage
	exit 0
	;;
esac

command -v cargo >/dev/null || die "cargo is required to build npm package binaries"
command -v node >/dev/null || die "node is required to validate npm package metadata"
command -v npm >/dev/null || die "npm is required to publish npm packages"

publish_args=(--access public "$@")

validate_package_metadata "${platform_package_dirs[@]}"
build_binaries
validate_binaries "${!platform_package_dirs[@]}"
publish_packages "${platform_package_dirs[@]}"
npm publish "${publish_args[@]}"
