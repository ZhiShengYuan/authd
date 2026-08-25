#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-$(git -C "${repo_dir}" describe --tags --always --dirty)}"
output="${2:-${repo_dir}/dist/authd}"

mkdir -p "$(dirname "${output}")"
cd "${repo_dir}"
CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${version}" \
  -o "${output}" \
  ./cmd/auth-gateway

echo "built ${output} (${version})"
