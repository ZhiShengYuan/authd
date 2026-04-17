# Branch Matrix Template

Use this template to track package-level branch coverage intent where Go's coverage tooling does not provide native branch-level reporting.

## Package: `<package-name>`

| Package Name | Function Name | Branch Description | Test Name | Status | Red Evidence | Green Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `<package-name>` | `<function-name>` | `happy path` | `<test-name>` | `covered` | `PR section or command log showing initial failure for new behavior, or N/A for legacy characterization` | `go test command output showing pass` |
| `<package-name>` | `<function-name>` | `failure path` | `<test-name>` | `uncovered` | `TBD` | `TBD` |

## Author Rules

- Replace every `TBD` before requesting review.
- For legacy behavior changes, add characterization-first evidence in `Red Evidence` by linking to the test that captured existing behavior before production edits.
- For new behavior, `Red Evidence` must show the failing test first.
- `Green Evidence` must reference a concrete test command and pass output.
- Keep function and branch labels aligned with real test names in this repository, for example `TestLoadConfig`, `TestPipelineRangeRequestPathNormalizationStripsQuery`, `TestValidateRejectsTamperedHMAC`, `TestVerifyPrefixIntegrityInvalidSignatureLength`.

## Status Values

- `covered`
- `uncovered`
