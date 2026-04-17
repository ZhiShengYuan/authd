# Mirror-Guard Auth Gateway API Reference

## Overview
Mirror-Guard Auth Gateway is a policy decision point that sits behind Nginx.
Nginx is the policy enforcement point and sends an `auth_request` subrequest to `GET /api/auth_inline` for protected traffic.
The gateway evaluates request context, policy rules, quota state, and one-time cookies, then returns a decision that Nginx enforces.

Integration model:
1. Client requests protected content from Nginx.
2. Nginx sends context headers to `GET /api/auth_inline`.
3. Gateway returns allow, challenge, reject, redirect, or drop outcome.
4. For browser challenge flow, client calls `GET /api/challenge`, solves PoW, then posts to `POST /api/verify_pow`.
5. Gateway issues a short-lived cookie and client retries original URL.

## Authentication Flow
1. **`auth_inline` decision**
   - Nginx subrequest calls `GET /api/auth_inline` with `X-Real-IP`, `X-URL`, `X-UA`, and forwarded telemetry headers.
   - Decision chain order is fixed: whitelist, blacklist, policy rule outcome, cookie check, then challenge or direct sign.
2. **Challenge required (browser path)**
   - If no valid one-time cookie is present and request is browser-like, gateway returns `401` and `X-Auth-Action: challenge`.
   - Nginx maps that to a challenge page redirect.
3. **Fetch challenge**
   - Browser calls `GET /api/challenge` with `X-Real-IP` and target URL context.
   - Gateway returns JSON `{prefix, difficulty, target}`.
4. **Submit PoW**
   - Browser posts `POST /api/verify_pow` with `prefix`, `nonce`, and optional `target_uri`.
   - Gateway verifies prefix integrity, subnet binding, computed difficulty, PoW validity, then nonce replay lock.
5. **Cookie-armed retry**
   - On success, gateway returns `302` with `Set-Cookie: auth_token=...` and `Location`.
   - Browser retries protected URL, `auth_inline` validates cookie, consumes token ID once, and returns allow.

Step-by-step sequence narrative:
1. Client requests `GET /releases/file.iso` from Nginx.
2. Nginx sends internal subrequest to `/auth/inline`, proxied to gateway `/api/auth_inline`.
3. Gateway evaluates whitelist, blacklist, policy rules, and cookie state.
4. Gateway returns one of: `200`, `401` with `X-Auth-Action: challenge`, `403`, `302` with `Location`, `444`, or `503`.
5. If challenge path is selected, Nginx sets `pow_target=<encoded original url>` cookie and redirects user to challenge UI.
6. Browser fetches `/api/challenge`, receives signed challenge prefix and difficulty.
7. Browser solves PoW and submits `/api/verify_pow` as form or JSON.
8. Gateway verifies submission, sets one-time `auth_token` cookie, redirects to target.
9. Browser retries original URL with `auth_token`, gateway validates bindings and one-time consumption, then allows request.

## Endpoint Matrix
| Method | Path | Purpose | Auth Required |
|---|---|---|---|
| GET | `/api/auth_inline` | Auth decision endpoint used by Nginx `auth_request` | Nginx internal subrequest context |
| GET | `/api/challenge` | Generates PoW challenge for browser flow | No prior auth cookie required |
| POST | `/api/verify_pow` | Verifies PoW submission and issues one-time auth cookie | Valid challenge solution required |
| GET | `/healthz` | Liveness probe endpoint | No |
| GET | `/metrics` | Prometheus metrics endpoint | No |

## Common Headers
| Header | Used By | Required | Purpose | Example |
|---|---|---|---|---|
| `X-Real-IP` | `/api/auth_inline`, `/api/challenge`, `/api/verify_pow` | Yes | Client IP source for subnet key, policy decisions, and subnet binding | `192.0.2.1` |
| `X-URL` | `/api/auth_inline`, `/api/challenge` | Expected (auth_inline), conditional (challenge via `pow_target` fallback) | Full target URL being authorized/challenged | `https://mirror.example.com/releases/file.iso` |
| `X-UA` | `/api/auth_inline`, `/api/challenge`, `/api/verify_pow` | Optional | User-Agent used for client classification and cookie UA digest binding | `Mozilla/5.0 (X11; Linux x86_64)` |
| `X-Request-ID` | `/api/auth_inline` | Optional | Request correlation ID, auto-generated if missing | `req-7f9c2d4a` |
| `X-Forwarded-Host` | `/api/auth_inline` | Optional | Preferred host context for policy route evaluation | `mirror.example.com` |
| `X-Host` | `/api/auth_inline` | Optional | Host fallback if `X-Forwarded-Host` is absent | `mirror.example.com` |
| `X-JA3-Hash` | `/api/auth_inline` | Optional | TLS fingerprint telemetry used in classification and logs | `d41d8cd98f00b204e9800998ecf8427e` |
| `Cookie` | all endpoints | Optional | Carries `auth_token` for inline auth and `pow_target` for challenge fallback target | `auth_token=<token>; pow_target=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso` |

## Cookie Semantics
Cookie behavior comes from `internal/cookie` and pipeline validation.

- **Name**: `auth_token`
- **Format**: base64url encoded payload plus HMAC-SHA256 signature
- **TTL**: default 15 seconds (`Max-Age=15`)
- **One-time use**: token ID is claimed once via `CookieConsumptionStore`; replay attempt fails validation path
- **Bindings checked on validate**:
  - subnet key from client IP (`IPv4 /24`, `IPv6 /56` via `subnet.DefaultKey`)
  - UA digest from `X-UA` (`SHA-256`, first 16 bytes hex)
  - normalized target path (query stripped)
- **Set-Cookie security flags**:
  - `Path=/`
  - `HttpOnly`
  - `Secure`
  - `SameSite=Lax`
  - `Max-Age=15` by default

`pow_target` cookie note:
- Nginx challenge redirect sets `pow_target=<url-escaped-target>; Path=/; SameSite=Lax`.
- `/api/challenge` uses this cookie only if `X-URL` header is missing.
- `pow_target` is a challenge helper cookie, not an auth cookie.

## Error Taxonomy
| Endpoint | HTTP Status | Error Code / Body | Meaning |
|---|---:|---|---|
| `/api/auth_inline` | `200` | none | Allowed by whitelist, valid cookie, allow rule, or direct sign under quota |
| `/api/auth_inline` | `401` | header `X-Auth-Action: challenge` | Browser challenge required |
| `/api/auth_inline` | `403` | none | Blacklisted, reject rule, or quota exceeded with no redirect URL |
| `/api/auth_inline` | `302` | `Location` header | Redirect rule, or quota exceeded with redirect URL |
| `/api/auth_inline` | `444` | none | Drop rule, Nginx-specific connection close status |
| `/api/auth_inline` | `503` | none | Panic recovery or state unavailable during quota check |
| `/api/challenge` | `400` | `invalid client ip` | Missing or unparsable client IP for subnet key |
| `/api/challenge` | `400` | `missing X-URL header` | No `X-URL` header and no `pow_target` fallback cookie |
| `/api/challenge` | `405` | `method not allowed` | Method must be `GET`; includes `Allow: GET` |
| `/api/challenge` | `500` | `internal server error` | Salt generation failure |
| `/api/verify_pow` | `400` | `{"error":"missing required fields"}` | `prefix` or `nonce` missing in form or JSON body |
| `/api/verify_pow` | `403` | `{"error":"invalid or expired prefix"}` | Prefix signature mismatch, malformed prefix, or expired prefix |
| `/api/verify_pow` | `403` | `{"error":"subnet mismatch"}` | Prefix subnet does not match caller subnet |
| `/api/verify_pow` | `403` | `{"error":"invalid proof of work difficulty"}` | Invalid configured difficulty bounds or computed difficulty <= 0 |
| `/api/verify_pow` | `403` | `{"error":"invalid proof of work"}` | Nonce does not satisfy leading-zero difficulty |
| `/api/verify_pow` | `403` | `{"error":"replay detected"}` | Nonce already seen in nonce store |
| `/api/verify_pow` | `405` | `method not allowed` | Method must be `POST`; includes `Allow: POST` |
| `/api/verify_pow` | `503` | `{"error":"internal state unavailable"}` | Nonce store unavailable during lock/check |
| `/api/verify_pow` | `503` | `internal server error` | Cookie issuance failure |

## Endpoints

### GET /api/auth_inline
Purpose: Nginx `auth_request` decision endpoint for protected resource requests.

Gateway contract versus Nginx transport:
- Public contract is `GET /api/auth_inline`.
- Nginx internal location `/auth/inline` uses `proxy_method POST` and proxies to `/api/auth_inline`.
- Treat this endpoint as a header-driven decision API. Body is not used.

Request headers consumed:
- Required in practice: `X-Real-IP`, `X-URL`
- Optional but used when present: `X-UA`, `X-Request-ID`, `X-Forwarded-Host`, `X-Host`, `X-JA3-Hash`, `Cookie`

Response headers emitted:
- `X-Auth-Action: challenge` on `401`
- `Location: <redirect-url>` on `302` when redirect URL is available

Decision matrix and status mapping:

| Order | Check | Outcome | Status |
|---:|---|---|---:|
| 1 | Subnet key missing | Challenge fallback path | `401` (`X-Auth-Action: challenge`) |
| 2 | IP matches whitelist | Allow immediately | `200` |
| 3 | IP matches blacklist | Reject immediately | `403` |
| 4 | Policy rule `Reject` | Reject | `403` |
| 5 | Policy rule `Redirect` | Redirect with `Location` when configured | `302` |
| 6 | Policy rule `Drop` | Drop request | `444` |
| 7 | Policy rule `Allow` | Allow (still quota-checked) | `200`, `302`, `403`, or `503` |
| 8 | Valid one-time cookie | Allow (quota-checked) | `200`, `302`, `403`, or `503` |
| 9 | Browser client without valid cookie | Challenge | `401` (`X-Auth-Action: challenge`) |
| 10 | Non-browser without valid cookie | Direct sign then allow (quota-checked) | `200`, `302`, `403`, or `503` |

Quota interaction for allow paths:
- For `ActionAccept` and `ActionDirectSign`, gateway increments quota by subnet.
- If quota store is unavailable, gateway returns `503`.
- If over quota and redirect URL is configured, gateway returns `302` with `Location`.
- If over quota and no redirect URL exists, gateway returns `403`.

Nginx `auth_request` integration example:

```nginx
location / {
    auth_request /auth/inline;
    auth_request_set $auth_action $upstream_http_x_auth_action;
    auth_request_set $auth_redirect_url $upstream_http_location;

    error_page 401 =302 @auth_challenge;
    error_page 403 =302 @quota_exceeded;
    error_page 500 502 503 504 = @auth_fallback;
}
```

Example gateway request from Nginx:

```http
GET /api/auth_inline HTTP/1.1
Host: auth-gateway.internal
X-Real-IP: 192.0.2.44
X-URL: https://mirror.example.com/releases/file.iso?download=1
X-UA: Mozilla/5.0 (X11; Linux x86_64)
X-Request-ID: req-a1302f48
X-Forwarded-Host: mirror.example.com
X-Host: mirror.example.com
X-JA3-Hash: 5d41402abc4b2a76b9719d911017c592
Cookie: auth_token=ZXlKaGJHY2lPaUpJVXpJMU5pSXNJ...
```

Example response variants:

```http
HTTP/1.1 200 OK
```

```http
HTTP/1.1 401 Unauthorized
X-Auth-Action: challenge
```

```http
HTTP/1.1 403 Forbidden
```

```http
HTTP/1.1 302 Found
Location: https://mirrors.example.net/fallback/releases/file.iso
```

```http
HTTP/1.1 444
```

```http
HTTP/1.1 503 Service Unavailable
```

### GET /api/challenge
Purpose: Generate PoW challenge for caller subnet and target URL.

Method:
- Only `GET` is accepted.

Required headers:
- `X-Real-IP`: required, used to derive subnet key.
- `X-URL`: conditionally required; if absent, the `pow_target` cookie is used as fallback (see target resolution order below).

Optional headers:
- `X-UA`: accepted and forwarded, not required for challenge generation.

Target resolution order:
1. Use `X-URL` header if present.
2. If missing, read `pow_target` cookie and URL-decode it.
3. If still missing, return `400` with `missing X-URL header`.

Success response (`200 application/json`):
- `prefix`: signed challenge string (contains target, subnet key, timestamp, salt, HMAC)
- `difficulty`: integer leading-zero requirement for PoW verification
- `target`: target URL that the solved challenge applies to

Example request:

```http
GET /api/challenge HTTP/1.1
Host: mirror.example.com
X-Real-IP: 192.0.2.44
X-URL: https://mirror.example.com/releases/file.iso
X-UA: Mozilla/5.0 (X11; Linux x86_64)
```

Example request using cookie fallback:

```http
GET /api/challenge HTTP/1.1
Host: mirror.example.com
X-Real-IP: 192.0.2.44
Cookie: pow_target=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso
```

Example success response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"prefix":"https://mirror.example.com/releases/file.iso|192.0.2.0/24|1713345600|f6c9a13d6bf2a9fe7db1e04c4dce11aa|4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2","difficulty":6,"target":"https://mirror.example.com/releases/file.iso"}
```

Error responses:

```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8

invalid client ip
```

```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8

missing X-URL header
```

```http
HTTP/1.1 405 Method Not Allowed
Allow: GET
Content-Type: text/plain; charset=utf-8

method not allowed
```

```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/plain; charset=utf-8

internal server error
```

### POST /api/verify_pow
Purpose: Verify PoW submission, issue short-lived one-time auth cookie, and redirect to target.

Method:
- Only `POST` is accepted.

Accepted request body formats:
1. Form body (`application/x-www-form-urlencoded` or multipart parsed by `ParseForm`)
   - `prefix` (required)
   - `nonce` (required)
   - `target_uri` (optional)
2. JSON body (`application/json`)
   - `prefix` (required)
   - `nonce` (required)
   - `target_uri` (optional)

**OpenAPI representation note**: The generated OpenAPI spec models only the JSON body format. The runtime also accepts `application/x-www-form-urlencoded` form submissions with the same field names (`prefix`, `nonce`, `target_uri`), but this dual-format support cannot be cleanly expressed in Swagger 2.0 without misrepresenting the contract. Integrators should prefer JSON; form submission is supported for browser compatibility.

Required headers:
- `X-Real-IP` (required for subnet validation)

Optional headers:
- `X-UA` (used to bind issued cookie)

Verification chain:
1. Parse submission and ensure `prefix` and `nonce` exist.
2. Verify signed prefix integrity and TTL.
3. Verify request subnet equals subnet embedded in prefix.
4. Compute and validate current PoW difficulty bounds.
5. Verify PoW (`sha256(prefix + nonce)` has required leading zeros).
6. Check and lock nonce in replay store.
7. Resolve `target_uri` from request value or prefix target.
8. Issue `auth_token` cookie bound to subnet, UA digest, and normalized target path.
9. Return `302` with `Location` and `Set-Cookie`.

Success response:
- Status: `302 Found`
- Headers:
  - `Location: <target_uri>`
  - `Set-Cookie: auth_token=...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=15`

Example request (form):

```http
POST /api/verify_pow HTTP/1.1
Host: mirror.example.com
Content-Type: application/x-www-form-urlencoded
X-Real-IP: 192.0.2.44
X-UA: Mozilla/5.0 (X11; Linux x86_64)

prefix=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso%7C192.0.2.0%2F24%7C1713345600%7Cf6c9a13d6bf2a9fe7db1e04c4dce11aa%7C4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2&nonce=0000006ab9f&target_uri=%2Freleases%2Ffile.iso
```

Example request (JSON):

```http
POST /api/verify_pow HTTP/1.1
Host: mirror.example.com
Content-Type: application/json
X-Real-IP: 192.0.2.44
X-UA: Mozilla/5.0 (X11; Linux x86_64)

{"prefix":"https://mirror.example.com/releases/file.iso|192.0.2.0/24|1713345600|f6c9a13d6bf2a9fe7db1e04c4dce11aa|4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2","nonce":"0000006ab9f","target_uri":"/releases/file.iso"}
```

Example success response:

```http
HTTP/1.1 302 Found
Location: /releases/file.iso
Set-Cookie: auth_token=ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbXRwWkNJNkltTnZiU0o5...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=15
```

Error responses and exact bodies:

```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8

{"error":"missing required fields"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

{"error":"invalid or expired prefix"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

{"error":"subnet mismatch"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

{"error":"invalid proof of work difficulty"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

{"error":"invalid proof of work"}
```

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8

{"error":"replay detected"}
```

```http
HTTP/1.1 405 Method Not Allowed
Allow: POST
Content-Type: text/plain; charset=utf-8

method not allowed
```

```http
HTTP/1.1 503 Service Unavailable
Content-Type: text/plain; charset=utf-8

{"error":"internal state unavailable"}
```

```http
HTTP/1.1 503 Service Unavailable
Content-Type: text/plain; charset=utf-8

internal server error
```

### GET /healthz
Purpose: Liveness endpoint for operations.

Response:
- `200 OK`
- Body: `ok`

Operational note:
- This endpoint is operational-only and excluded from the OpenAPI contract.

### GET /metrics
Purpose: Prometheus metrics endpoint for operations.

Response:
- `200 OK` with Prometheus text exposition.

Operational note:
- This endpoint is operational-only and excluded from the OpenAPI contract.

## Operational Endpoints
`/healthz` and `/metrics` are operational endpoints.
They are intentionally excluded from the public OpenAPI specification for client-facing auth integrations.

## Regeneration
Regenerate OpenAPI artifacts with:

```bash
./scripts/openapi.sh
```

Notes:
- This script runs `swag init` and writes generated files under `docs/openapi`.
- Keep `docs/api.md` as the human-readable contract companion to generated OpenAPI artifacts.
