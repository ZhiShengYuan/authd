# Branch Matrix

## Package: `handler`

| Package Name | Function Name | Branch Description | Test Name | Status |
| --- | --- | --- | --- | --- |
| `handler` | `VerifyPoWHandler.ServeHTTP` | `method is not POST returns 405` | `TBD` | `uncovered` |
| `handler` | `VerifyPoWHandler.ServeHTTP` | `parseSubmission fails for missing fields returns 400` | `TBD` | `uncovered` |
| `handler` | `VerifyPoWHandler.ServeHTTP` | `target_uri empty uses prefix target fallback` | `TBD` | `uncovered` |
| `handler` | `VerifyPoWHandler.ServeHTTP` | `NonceStore.CheckAndLock returns error -> 503` | `TBD` | `uncovered` |
| `handler` | `VerifyPoWHandler.ServeHTTP` | `cookie manager issue error -> 503` | `TBD` | `uncovered` |
| `handler` | `parseSubmission` | `form parse succeeds but target_uri empty then JSON decode fallback` | `TBD` | `uncovered` |
| `handler` | `ChallengeHandler.ServeHTTP` | `method is not GET returns 405` | `TBD` | `uncovered` |
| `handler` | `ChallengeHandler.ServeHTTP` | `invalid client IP returns 400` | `TBD` | `uncovered` |
| `handler` | `ChallengeHandler.ServeHTTP` | `missing X-URL and no pow_target cookie returns 400` | `TBD` | `uncovered` |
| `handler` | `ChallengeHandler.ServeHTTP` | `pow_target cookie present but query-unescape fails` | `TBD` | `uncovered` |

## Status Values

- `covered`
- `uncovered`
