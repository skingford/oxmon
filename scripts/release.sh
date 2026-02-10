#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/release.sh [--version <x.y.z>] [--no-push] [--skip-check]
  scripts/release.sh [<x.y.z>] [--no-push] [--skip-check]

Behavior:
  - If version is omitted, patch version is auto-incremented (e.g. 0.1.1 -> 0.1.2)
  - Updates [workspace.package].version in Cargo.toml
  - Runs cargo check --workspace (unless --skip-check)
  - Commits Cargo.toml + Cargo.lock
  - Creates annotated tag v<version>
  - Pushes main + tag by default (use --no-push to skip)

Examples:
  scripts/release.sh
  scripts/release.sh 0.1.2
  scripts/release.sh --version 0.1.2 --no-push
USAGE
}

die() {
  echo "[release] error: $*" >&2
  exit 1
}

require_clean_tree() {
  if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is not clean. Commit/stash changes first."
  fi
}

read_current_version() {
  awk '
    /^\[workspace\.package\]$/ { in_pkg=1; next }
    /^\[/ { in_pkg=0 }
    in_pkg && /^version = / {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.toml
}

bump_patch() {
  local version="$1"
  local major minor patch
  IFS='.' read -r major minor patch <<<"$version"
  echo "${major}.${minor}.$((patch + 1))"
}

update_workspace_version() {
  local new_version="$1"
  awk -v new_version="$new_version" '
    /^\[workspace\.package\]$/ { in_pkg=1; print; next }
    /^\[/ { in_pkg=0; print; next }
    in_pkg && /^version = / { print "version = \"" new_version "\""; next }
    { print }
  ' Cargo.toml > Cargo.toml.tmp
  mv Cargo.toml.tmp Cargo.toml
}

validate_semver() {
  local version="$1"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

target_version=""
push_tag=true
run_check=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -v|--version)
      [[ $# -ge 2 ]] || die "--version requires a value"
      target_version="$2"
      shift 2
      ;;
    --push)
      push_tag=true
      shift
      ;;
    --no-push)
      push_tag=false
      shift
      ;;
    --skip-check)
      run_check=false
      shift
      ;;
    *)
      if [[ -z "$target_version" ]]; then
        target_version="$1"
        shift
      else
        die "unexpected argument: $1"
      fi
      ;;
  esac
done

[[ -f Cargo.toml ]] || die "Cargo.toml not found; run from repository root"

current_version="$(read_current_version)"
[[ -n "$current_version" ]] || die "failed to read current workspace version"

if [[ -z "$target_version" ]]; then
  target_version="$(bump_patch "$current_version")"
fi

validate_semver "$target_version" || die "invalid version '$target_version' (expect x.y.z)"
[[ "$target_version" != "$current_version" ]] || die "target version equals current version: $current_version"

tag_name="v${target_version}"
if git rev-parse -q --verify "refs/tags/${tag_name}" >/dev/null; then
  die "tag already exists: ${tag_name}"
fi

require_clean_tree

echo "[release] current version: ${current_version}"
echo "[release] target version:  ${target_version}"

update_workspace_version "$target_version"

if [[ "$run_check" == true ]]; then
  echo "[release] running cargo check --workspace"
  cargo check --workspace
else
  echo "[release] skip cargo check"
fi

if [[ -f Cargo.lock ]]; then
  git add Cargo.toml Cargo.lock
else
  git add Cargo.toml
fi

git commit -m "chore(release): bump version to ${target_version}"
git tag -a "${tag_name}" -m "${tag_name}"

echo "[release] created commit + tag: ${tag_name}"

if [[ "$push_tag" == true ]]; then
  echo "[release] pushing main and ${tag_name}"
  git push origin main
  git push origin "${tag_name}"
  echo "[release] pushed successfully"
else
  echo "[release] not pushed. Run:"
  echo "  git push origin main"
  echo "  git push origin ${tag_name}"
fi
