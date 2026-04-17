# PR TDD Evidence Template

Copy into every behavior-changing PR description.

## Change Type

- [ ] Legacy behavior change
- [ ] New behavior
- [ ] Refactor only

## Red Evidence

### Legacy behavior change, characterization-first

- Test(s) added or expanded before production edits:
  - `...`
- Red or gap evidence:
  - `...`

### New behavior, failing test first

- Failing test name and package:
  - `...`
- Failure output snippet captured before production edits:
  - `...`

## Green Evidence

```bash
go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out
go tool cover -func=coverage.out
go test -race ./...
```

- Command output snippets:
  - `go test ./... -coverpkg=./... -covermode=atomic -coverprofile=coverage.out`:
    - `...`
  - `go tool cover -func=coverage.out`:
    - `...`
  - `go test -race ./...`:
    - `...`

## Minimal Change to Green

- Production files changed to satisfy red test:
  - `...`
- Why change is minimal:
  - `...`

## Refactor Phase, Must Stay Green

- Refactor commit(s) or section:
  - `...`
- Proof tests stayed green during refactor:
  - `...`

## Branch Matrix Updates

- Updated docs file(s):
  - `docs/branch-matrices/...`
- Updated rows include concrete test names and red/green evidence links:
  - `...`

## Reviewer Notes

- [ ] Red, green, refactor evidence complete
- [ ] Command-of-record coverage and race outputs present
- [ ] Branch matrix updates present and complete
- [ ] Merge not blocked
