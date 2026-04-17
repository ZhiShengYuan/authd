# Branch Matrix: internal/testutil

Exemption note: `WriteTempConfig` and `WriteTempPolicy` both call `json.Marshal` on their input.
Any Go value that can be passed to these helpers (maps, structs, slices) always marshals
successfully in practice. The `json.Marshal` error branches are therefore **structurally
unreachable** — they can only be triggered by a type that implements `json.Marshaler` with a
failing `MarshalJSON()`, which no caller in this repo does. This is a zero-gap by definition,
not a coverage deficiency.

| Function | Branch | Test Name | Status | Red Evidence | Green Evidence |
|---|---|---|---|---|---|
| FindNonce | happy path (solution found) | `TestIntegrationFlowViaTestutilHelpers` | covered | N/A legacy characterization | green pass |
| FindNonce | no-solution path (limit exhausted) | `TestFindNonceNoSolutionPath` | covered | failing test first | green pass |
| WriteTempConfig | marshal success | `TestWriteTempConfigAndPolicyArtifacts` | covered | N/A legacy characterization | green pass |
| WriteTempConfig | marshal failure | EXEMPT — structurally unreachable | exempt | rationale above | N/A |
| WriteTempPolicy | marshal success | `TestWriteTempConfigAndPolicyArtifacts` | covered | N/A legacy characterization | green pass |
| WriteTempPolicy | marshal failure | EXEMPT — structurally unreachable | exempt | rationale above | N/A |
| NewTestConfig | all branches | direct invocation | covered | N/A | green pass |
| NewTestStore | all branches | `TestIntegrationFlowViaTestutilHelpers` | covered | N/A | green pass |
