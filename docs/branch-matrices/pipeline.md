# Branch Matrix

## Package: `pipeline`

| Package Name | Function Name | Branch Description | Test Name | Status |
| --- | --- | --- | --- | --- |
| `pipeline` | `Pipeline.ServeHTTP` | `missing subnet key executes fallback challenge path` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.ServeHTTP` | `policy returns redirect action and marks fallback mode` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.ServeHTTP` | `policy returns drop action (status 444)` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.executeAction` | `ActionRedirect without redirect URL still returns 302` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.executeAction` | `ActionDrop returns 444` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.hasValidCookie` | `cookie manager nil or state store nil rejects cookie path` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.hasValidCookie` | `CookieConsumptionStore nil rejects token after validation` | `TBD` | `uncovered` |
| `pipeline` | `Pipeline.overQuota` | `QuotaStore.Increment returns error propagates failure` | `TBD` | `uncovered` |
| `pipeline` | `normalizePath` | `URL parse fails and input starts with '?' returns '/'` | `TBD` | `uncovered` |
| `pipeline` | `matchIP` | `entry is malformed CIDR and safely skipped` | `TBD` | `uncovered` |

## Status Values

- `covered`
- `uncovered`
