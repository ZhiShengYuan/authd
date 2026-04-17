# Auth Gateway Nginx Integration

This directory provides a ready-to-include Nginx PEP configuration for the Mirror-Guard Go PDP.

## Files

- `auth-gateway.conf`: main server/auth_request integration config.
- `nginx.test.conf`: minimal config for CI syntax validation (`nginx -t`).

## What `auth-gateway.conf` does

- For protected `location /`, calls PDP auth via `auth_request /auth/inline`.
- Uses internal-only `location = /auth/inline` with:
  - `proxy_method POST`
  - `proxy_pass_request_body off`
  - Full header forwarding set (IP, URL, UA, TLS, JA3/JA4, H2, GeoIP2, TCP, Cookie).
- Routes outcomes through named locations:
  - `@auth_challenge`: sets `pow_target` cookie and redirects to `/testpow/`
  - `@quota_exceeded`: redirects to fallback mirror URL
  - `@blacklist_reject`: returns `403`
  - `@auth_fallback`: fail-open path with `limit_req` + `limit_rate`
- Exposes public endpoints:
  - `/testpow/`
  - `/api/challenge`
  - `/api/verify_pow`
  - `/healthz`
  - `/metrics`

## Fail-open behavior

Fallback uses subnet-oriented throttling:

```nginx
limit_req_zone $binary_remote_addr zone=subnet_fallback:10m rate=30r/m;
...
location @auth_fallback {
    limit_req zone=subnet_fallback burst=20 nodelay;
    limit_rate 1m;
    ...
}
```

This keeps protected traffic available when PDP is unavailable, instead of hard-failing downloads.

## Deploy steps

1. Install `nginx/auth-gateway.conf` into your Nginx include tree under `http {}`.
2. Ensure Go PDP is listening on unix socket:
   - `/run/auth-gateway/go-auth.sock`
3. Ensure protected backend is reachable at:
   - `http://unix:/tmp/nginx.sock`
4. Place challenge static assets under:
   - `/var/www/testpow/`
5. Validate config:

```bash
nginx -t -c /home/kexi/mirror-auth-backend/nginx/nginx.test.conf
```

6. Reload Nginx after validation.

## Notes

- Keep `/auth/inline` marked `internal`; never expose it publicly.
- Do not trust identity headers from untrusted downstream peers.
- If you deploy on 443, uncomment TLS `listen` and certificate directives in `auth-gateway.conf`.
