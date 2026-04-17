# Reviewer TDD Blocking Checklist

Use this checklist during review. If any required item is missing, request changes and block merge.

## 1. Red, Green, Refactor Evidence

- [ ] PR shows characterization-first evidence for legacy behavior changes.
- [ ] PR shows failing-test-first evidence for new behavior.
- [ ] PR shows minimal production change from red to green.
- [ ] PR separates refactor from behavior change, or clearly proves refactor stayed green.

Block merge if any box above is unchecked.

## 2. Repo Command Enforcement

Confirm these exact commands are present in PR evidence:

```bash
go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out
go tool cover -func=coverage.out
go test -race ./...
```

- [ ] Coverage command-of-record output is included.
- [ ] `go tool cover -func=coverage.out` output is included.
- [ ] `go test -race ./...` output is included.

Block merge if author used only per-package coverage output for acceptance.

## 3. Branch Matrix Enforcement

- [ ] Author updated relevant file(s) under `docs/branch-matrices/`.
- [ ] Changed branches map to concrete test names.
- [ ] Red and green evidence links are filled, no `TBD` left for changed branches.
- [ ] Status reflects real coverage intent for each changed branch.

Block merge if branch matrix entries for changed behavior are missing or unresolved.

## 4. Repository Pattern Checks

Validate tests follow existing repository style and are behavior-assertive:

- `internal/config/config_test.go`: table-driven validation characterization
- `internal/pipeline/pipeline_test.go`: `httptest` request-path and error-path assertions
- `internal/cookie/cookie_test.go`: token tamper and binding rejection assertions
- `internal/pow/pow_test.go`: prefix integrity parse/validation branch assertions

- [ ] New tests assert outcomes and failure semantics, not just line execution.
- [ ] Behavior changes are covered by package-level tests tied to branch matrix rows.

Block merge on assertion-free or weakly asserted tests.

## Reviewer Decision

- [ ] Approve only when all required sections above are complete.
- [ ] Otherwise request changes with a direct note: `Blocked: missing TDD enforcement evidence`.
