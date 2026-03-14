#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_files="$(mktemp)"
trap 'rm -f "$tmp_files"' EXIT

git ls-files \
  '*.rs' '*.sh' '*.md' '*.toml' '*.json' '*.yml' '*.yaml' '*.proto' \
  ':!:Cargo.lock' \
  ':!:target/**' \
  ':!:.git/**' >"$tmp_files"

scan() {
  local description="$1"
  local pattern="$2"
  local output

  if output="$(xargs rg -n -H -I -e "$pattern" <"$tmp_files" || true)" && [[ -n "$output" ]]; then
    echo "Potential secret exposure detected: $description" >&2
    echo "$output" >&2
    return 1
  fi

  return 0
}

scan_with_allowlist() {
  local description="$1"
  local pattern="$2"
  local allowlist="$3"
  local output

  output="$(xargs rg -n -H -I -e "$pattern" <"$tmp_files" || true)"
  if [[ -n "$output" ]]; then
    output="$(printf '%s\n' "$output" | rg -v "$allowlist" || true)"
  fi

  if [[ -n "$output" ]]; then
    echo "Potential secret exposure detected: $description" >&2
    echo "$output" >&2
    return 1
  fi

  return 0
}

scan "private key material" 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY'
scan "AWS access key id" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
scan "generic access key id" 'AKID[0-9A-Za-z]{12,}'
scan "OpenAI-style key" 'sk-[A-Za-z0-9]{16,}'
scan "GitHub token" 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}'

scan_with_allowlist \
  "hard-coded token/secret assignments" \
  '("(auth_token|jwt_secret|secret_key|secret_id|api_key|access_key_secret)"\s*:\s*"[^"]+"|^[[:space:]#]*(auth_token|jwt_secret)\s*=\s*"[^"]+")' \
  'example|your-|YOUR_|test|changeme|change-me|legacy|temp-|placeholder|dummy|mock|xxx|<|oxmon_example|my-secret|secure123|\$\{|\$\(|""'

scan_with_allowlist \
  "DingTalk webhook token" \
  'https://oapi\.dingtalk\.com/robot/send\?access_token=[^"`[:space:]]+' \
  'YOUR_TOKEN|example|test|xxx|\.\.\.'

echo "No obvious secret exposures found."
