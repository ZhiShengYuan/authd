# Branch Matrix

## Package: `policy`

| Package Name | Function Name | Branch Description | Test Name | Status |
| --- | --- | --- | --- | --- |
| `policy` | `Set.Evaluate` | `set is nil and browser client returns challenge` | `TBD` | `uncovered` |
| `policy` | `Set.Evaluate` | `set is nil and non-browser client returns direct_sign` | `TBD` | `uncovered` |
| `policy` | `Set.Evaluate` | `no rule match and metadata/generic path falls through to allow` | `TBD` | `uncovered` |
| `policy` | `matchesRule` | `rule.PathPrefix matches host+path fallback` | `TBD` | `uncovered` |
| `policy` | `LoadExternal` | `empty path returns default set` | `TBD` | `uncovered` |
| `policy` | `LoadExternal` | `path does not exist returns default set` | `TBD` | `uncovered` |
| `policy` | `LoadExternal` | `file exists but zero bytes returns default set` | `TBD` | `uncovered` |
| `policy` | `toSet` | `invalid quota_defaults.default_window parse error` | `TBD` | `uncovered` |
| `policy` | `convertRule` | `missing rule name returns validation error` | `TBD` | `uncovered` |
| `policy` | `convertRule` | `invalid client_class returns validation error` | `TBD` | `uncovered` |
| `policy` | `convertRule` | `invalid download_behavior returns validation error` | `TBD` | `uncovered` |
| `policy` | `convertRule` | `invalid quota_window parse error` | `TBD` | `uncovered` |
| `policy` | `parseAction` | `unknown action returns validation error` | `TBD` | `uncovered` |
| `policy` | `validateCIDRList` | `invalid CIDR entry returns validation error` | `TBD` | `uncovered` |

## Status Values

- `covered`
- `uncovered`
