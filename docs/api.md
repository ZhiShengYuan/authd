# Mirror-Guard Auth Gateway API Reference

## Overview
Mirror-Guard Auth Gateway now exposes a 4-endpoint internal JSON API for challenge and ticket workflows. The legacy auth-inline and cookie-redirect gateway flow has been removed.

## Endpoint Matrix
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/challenges` | Configure and issue a challenge prefix |
| POST | `/api/challenges/verify` | Verify solved challenge response |
| POST | `/api/tickets` | Issue ticket for a bind matrix |
| POST | `/api/tickets/verify` | Verify and consume issued ticket |
| GET | `/healthz` | Liveness probe |
| GET | `/metrics` | Prometheus metrics |

## Challenge Endpoints

### POST /api/challenges
Accepts JSON body:

```json
{
  "challenge_id": "challenge-1",
  "difficulty": 1,
  "bind_matrix": {
    "url": "/protected",
    "ip": "198.51.100.10",
    "ua": "Mozilla/5.0"
  }
}
```

Returns `201 Created` with challenge data including `prefix`, `difficulty`, and `challenge_id`.

### POST /api/challenges/verify
Accepts JSON body:

```json
{
  "challenge_id": "challenge-1",
  "nonce": "12345",
  "prefix": "<prefix>"
}
```

Returns `200 OK` with `{ "valid": true|false }` on successful verification flow and typed error envelopes for not-found/expired/replayed challenges.

## Ticket Endpoints

### POST /api/tickets
Accepts JSON body:

```json
{
  "bind_matrix": {
    "url": "/resource",
    "ip": "192.168.0.10",
    "ua": "Mozilla/5.0"
  },
  "uses": 3
}
```

Returns `201 Created` with a signed `ticket`.

### POST /api/tickets/verify
Accepts JSON body:

```json
{
  "ticket": "<signed-ticket>",
  "bind_matrix": {
    "url": "/resource",
    "ip": "192.168.0.10",
    "ua": "Mozilla/5.0"
  }
}
```

Returns `200 OK` with `{ "valid": true|false }` or typed error envelopes for invalid/expired/exhausted tickets.

## Operational Endpoints
`/healthz` and `/metrics` remain operational endpoints and are intentionally outside the client-facing auth contract.
