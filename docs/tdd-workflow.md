# Repository TDD Workflow Enforcement

This repository uses strict red, green, refactor. Coverage numbers are required, but they are not accepted without behavior evidence.

## Scope

- Applies to all behavior changes in Go packages under `cmd/` and `internal/`.
- Applies to both authors and reviewers.
- Works with the existing stdlib test stack in this repo (`testing`, `httptest`, deterministic helpers in `internal/testutil`).

## Command of Record

Run these commands from repository root:

```bash
go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out
go tool cover -func=coverage.out
go test -race ./...
```

Author requirement: include command output snippets in PR evidence sections.

Reviewer requirement: block merge if command-of-record output is missing or replaced with per-package-only shortcuts.

## Workflow, Required Order

### 1) Characterization-first for legacy behavior changes

If you are changing existing behavior in code that already exists:

1. Add or expand a characterization test first, before production edits.
2. Prove current behavior with a failing or gap-revealing test when behavior is wrong or missing.
3. Only then change production code.

Use existing repo patterns:

- `internal/config/config_test.go` table-driven validation branches in `TestLoadConfig`
- `internal/pipeline/pipeline_test.go` branch and recovery tests like `TestPipelineMalformedXRealIPIsSafelyRejected`
- `internal/cookie/cookie_test.go` token validation negative cases like `TestValidateRejectsTamperedHMAC`
- `internal/pow/pow_test.go` parse and integrity branches like `TestVerifyPrefixIntegrityInvalidSignatureLength`

### 2) Failing test first for new behavior

If you are adding new behavior:

1. Write a test that fails for the new behavior.
2. Capture red evidence in PR text or command log.
3. Do not edit production code until the failure is shown.

### 3) Minimal production change to green

After red is proven:

1. Make the smallest production change that satisfies the failing test.
2. Run focused tests first, then run command-of-record.
3. Keep assertions behavior-focused, not line-execution-focused.

### 4) Refactor only while staying green

Refactor is allowed only after green.

1. Keep tests passing after each refactor step.
2. No behavior changes during refactor commits.
3. Re-run command-of-record and race tests after refactor.

## Evidence Required in Pull Requests

Every PR must contain all items below:

- Red evidence:
  - Legacy change: characterization-first test reference and output
  - New behavior: failing test output before production edits
- Green evidence:
  - Relevant package test output
  - `go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out`
  - `go tool cover -func=coverage.out`
  - `go test -race ./...`
- Branch matrix updates in `docs/branch-matrices/*.md` for changed branches

## Merge Blocking Policy

A reviewer must request changes and block merge when any condition below is true:

- No red evidence for either characterization-first or failing-test-first.
- Green evidence does not include the command-of-record or race test.
- Branch matrix entries for changed behavior remain `uncovered` or `TBD`.
- Tests only execute lines without behavior assertions.
- Refactor changes are mixed with unproven behavior changes.

## Quick Author Checklist

- [ ] Legacy behavior change started with characterization test.
- [ ] New behavior started with a failing test.
- [ ] Production edits were minimal to reach green.
- [ ] Refactor happened only after green, and stayed green.
- [ ] Ran `go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out`.
- [ ] Ran `go tool cover -func=coverage.out`.
- [ ] Ran `go test -race ./...`.
- [ ] Updated `docs/branch-matrices/*.md` with concrete test names and red/green evidence references.
