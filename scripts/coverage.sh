#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  rm -f coverage.out
}

trap cleanup EXIT

go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out

cover_output=$(go tool cover -func=coverage.out)
printf "%s\n" "$cover_output"

total_line=""
while IFS= read -r line; do
  case "$line" in
    total:*)
      total_line="$line"
      ;;
  esac
done <<< "$cover_output"

if [ -z "$total_line" ]; then
  printf "ERROR: coverage total line not found in go tool cover output\n" >&2
  exit 1
fi

if [[ "$total_line" =~ ^total:[[:space:]]+\(statements\)[[:space:]]+([0-9]+\.[0-9]+%)$ ]]; then
  total_percent="${BASH_REMATCH[1]}"
else
  printf "ERROR: unable to parse coverage total from line: %s\n" "$total_line" >&2
  exit 1
fi

if [ "$total_percent" != "100.0%" ]; then
  printf "ERROR: repository coverage gate failed (expected 100.0%%, got %s)\n" "$total_percent" >&2
  exit 1
fi

printf "Coverage gate passed at %s\n" "$total_percent"
