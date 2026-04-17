# Branch Matrix

## Package: `state`

| Package Name | Function Name | Branch Description | Test Name | Status |
| --- | --- | --- | --- | --- |
| `state` | `QuotaStore.Increment` | `subnetKey is empty returns errEmptyKey` | `TBD` | `uncovered` |
| `state` | `QuotaStore.Increment` | `window <= 0 uses DefaultQuotaWindow` | `TBD` | `uncovered` |
| `state` | `QuotaStore.Increment` | `existing entry with different window updates entry.window` | `TBD` | `uncovered` |
| `state` | `QuotaStore.Get` | `empty subnet key returns 0` | `TBD` | `uncovered` |
| `state` | `QuotaStore.Get` | `entry missing returns 0` | `TBD` | `uncovered` |
| `state` | `QuotaStore.Size` | `nil receiver returns 0` | `TBD` | `uncovered` |
| `state` | `NonceStore.CheckAndLock` | `ip or nonce empty returns errEmptyKey` | `TBD` | `uncovered` |
| `state` | `NonceStore.CheckAndLock` | `ttl <= 0 uses DefaultNonceTTL` | `TBD` | `uncovered` |
| `state` | `NonceStore.CheckAndLock` | `existing lock value has invalid type returns error` | `TBD` | `uncovered` |
| `state` | `NonceStore.Size` | `nil receiver returns 0` | `TBD` | `uncovered` |
| `state` | `CookieConsumptionStore.Claim` | `tokenID empty returns false` | `TBD` | `uncovered` |
| `state` | `CookieConsumptionStore.Claim` | `existing claim value has invalid type returns false` | `TBD` | `uncovered` |
| `state` | `CookieConsumptionStore.Size` | `nil receiver returns 0` | `TBD` | `uncovered` |

## Status Values

- `covered`
- `uncovered`
