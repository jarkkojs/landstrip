#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

die() {
	echo "$1" >&2
	exit 1
}

ver_gt() {
	if   (( $1 > $4 )); then return 0
	elif (( $1 == $4 && $2 > $5 )); then return 0
	elif (( $1 == $4 && $2 == $5 && $3 > $6 )); then return 0
	else return 1
	fi
}

committed=0
npm_package_jsons=(
	package.json
	npm/darwin-arm64/package.json
	npm/darwin-x64/package.json
	npm/linux-x64/package.json
	npm/win32-x64/package.json
)

cleanup() {
	local status=$?
	if (( status != 0 && !committed )); then
		git restore -- Cargo.toml Cargo.lock man/man1/landstrip.1 \
			"${npm_package_jsons[@]}" \
			2>/dev/null || true
	fi
	return "$status"
}
trap cleanup EXIT

next_ver="${1:-}"
[[ -n "$next_ver" ]] || die "usage: scripts/release.sh <next-version>"

[[ "$next_ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
	|| die "invalid version: $next_ver"
next_a="${BASH_REMATCH[1]}"
next_b="${BASH_REMATCH[2]}"
next_c="${BASH_REMATCH[3]}"

branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" \
	|| die "HEAD is detached; check out a branch before releasing"

[[ -z "$(git status --porcelain)" ]] \
	|| die "working directory is not clean"

[[ -z "$(git tag -l "$next_ver")" ]] \
	|| die "tag $next_ver already exists"

cur_ver="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)".*/\1/p' Cargo.toml | head -1)" \
	|| die "cannot find version in Cargo.toml"
[[ -n "$cur_ver" ]] || die "cannot find version in Cargo.toml"

[[ "$cur_ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
	|| die "cannot parse version components from: $cur_ver"
cur_a="${BASH_REMATCH[1]}"
cur_b="${BASH_REMATCH[2]}"
cur_c="${BASH_REMATCH[3]}"

ver_gt "$next_a" "$next_b" "$next_c" "$cur_a" "$cur_b" "$cur_c" \
	|| die "$next_ver is not greater than current $cur_ver"

man_page="man/man1/landstrip.1"
[[ -f "$man_page" ]] || die "missing man page: $man_page"

command -v node >/dev/null || die "node is required to update npm package versions"

sed -i -E "s/(^[[:space:]]*version[[:space:]]*=[[:space:]]*\")${cur_ver//./\\.}(\")/\1$next_ver\2/" Cargo.toml
grep -q "^version = \"$next_ver\"" Cargo.toml \
	|| die "failed to update version in Cargo.toml"

cargo metadata --format-version 1 >/dev/null
grep -A2 '^name = "landstrip"' Cargo.lock | grep -q "^version = \"$next_ver\"" \
	|| die "failed to update version in Cargo.lock"

node - "$next_ver" "${npm_package_jsons[@]}" <<'NODE'
const fs = require('node:fs');

const [nextVersion, ...packagePaths] = process.argv.slice(2);
const packages = packagePaths.map((packagePath) => [
  packagePath,
  JSON.parse(fs.readFileSync(packagePath, 'utf8')),
]);
const root = packages[0][1];

root.version = nextVersion;

for (const [, data] of packages.slice(1)) {
  data.version = nextVersion;

  if (!Object.prototype.hasOwnProperty.call(root.optionalDependencies, data.name)) {
    throw new Error(`package.json missing optional dependency ${data.name}`);
  }

  root.optionalDependencies[data.name] = nextVersion;
}

for (const [packagePath, data] of packages) {
  fs.writeFileSync(packagePath, `${JSON.stringify(data, null, 2)}\n`);
}
NODE

cargo clippy --all-targets --locked

date="$(LC_TIME=C date '+%B %e, %Y' | sed 's/  / /')"
sed -i -E "s/^\\.Dd .*/.Dd $date/" "$man_page"
grep -Fxq ".Dd $date" "$man_page" \
	|| die "failed to update $man_page"

git rev-parse -q --verify "refs/tags/$cur_ver" >/dev/null \
	|| die "current version tag $cur_ver does not exist"
range="${cur_ver}..HEAD"

log=""
while IFS=$'\x1f' read -r subj author; do
	log+="- $subj ($author)"$'\n'
done < <(git log --pretty=tformat:'%s%x1f%an' --no-merges "$range")
log="${log%$'\n'}"

git commit -a -s -m "Bump the version to $next_ver"
committed=1

sob="Signed-off-by: $(git config user.name) <$(git config user.email)>"
printf 'landstrip %s\n\n%s\n\n%s\n' "$next_ver" "$log" "$sob" | git tag -s "$next_ver" -F -

echo "tagged $next_ver"
