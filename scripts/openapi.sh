#!/usr/bin/env bash

set -euo pipefail

main() {
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local output_dir="${repo_root}/docs/openapi"

  cd "$repo_root"
  mkdir -p "$output_dir"

  if go run github.com/swaggo/swag/cmd/swag@v1.16.4 init \
    -g cmd/auth-gateway/main.go \
    -o docs/openapi \
    --parseInternal \
    --generatedTime=false; then
    local docs_go="docs/openapi/docs.go"
    if [ -f "$docs_go" ]; then
      if ! grep -q '^//go:build ignore$' "$docs_go"; then
        local tmp_file
        tmp_file="$(mktemp)"
        {
          printf "//go:build ignore\n"
          printf "\n"
          cat "$docs_go"
        } > "$tmp_file"
        mv "$tmp_file" "$docs_go"
      fi
    fi

    printf "OpenAPI docs generated successfully in %s\n" "$output_dir"
  else
    printf "ERROR: OpenAPI docs generation failed\n" >&2
    exit 1
  fi
}

main "$@"
