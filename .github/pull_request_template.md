## Summary

- Describe what changed and why.

## Required Validation

- [ ] I ran `./scripts/coverage.sh` (repo-wide `go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out` + strict `go tool cover -func` total gate at `100.0%`).
- [ ] I ran `./scripts/race.sh` (`go test -race ./...`).

## TDD Evidence (Required)

- [ ] **New behavior**: I wrote a failing test first, observed it fail, then implemented code to make it pass (red-green-refactor).
- [ ] **Legacy behavior change**: I added a characterization test first that captures pre-change behavior before modifying implementation.
- [ ] I included test names or command output in the PR description to show the failing-first or characterization-first step.
