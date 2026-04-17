# Mirror-Guard Auth Gateway API 参考文档

## 概述

Mirror-Guard Auth Gateway（镜像守卫认证网关）是一个策略决策点，部署在 Nginx 后端。Nginx 作为策略执行点，对受保护流量发送 `auth_request` 子请求到 `GET /api/auth_inline`。网关评估请求上下文、策略规则、配额状态和一次性 Cookie，然后返回由 Nginx 执行的决策结果。

集成流程：
1. 客户端向 Nginx 请求受保护内容
2. Nginx 携带 `X-Real-IP`、`X-URL`、`X-UA` 及转发遥测头向 `GET /api/auth_inline` 发送内部子请求
3. 网关返回允许（allow）、挑战（challenge）、拒绝（reject）、重定向（redirect）或丢弃（drop）结果
4. 对于浏览器挑战流程，客户端调用 `GET /api/challenge`，解决 PoW（工作量证明），然后提交到 `POST /api/verify_pow`
5. 网关颁发短命 Cookie，客户端重试原始 URL

## 认证流程

### 1. `auth_inline` 决策
- Nginx 子请求调用 `GET /api/auth_inline`，携带 `X-Real-IP`、`X-URL`、`X-UA` 和转发的遥测头
- 决策链顺序固定：白名单 → 黑名单 → 策略规则结果 → Cookie 检查 → 挑战或直接签章

### 2. 需要挑战（浏览器路径）
- 若不存在有效的一次性 Cookie 且请求类似浏览器，网关返回 `401` 和 `X-Auth-Action: challenge` 头
- Nginx 将此映射为挑战页面重定向

### 3. 获取挑战
- 浏览器使用 `X-Real-IP` 和目标 URL 上下文调用 `GET /api/challenge`
- 网关返回 JSON：`{prefix, difficulty, target}`

### 4. 提交 PoW
- 浏览器提交 `POST /api/verify_pow`，携带 `prefix`、`nonce` 和可选的 `target_uri`
- 网关验证前缀完整性、子网绑定、计算难度、PoW 有效性和 nonce 重放锁

### 5. 携带 Cookie 重试
- 成功后，网关返回 `302`，携带 `Set-Cookie: auth_token=...` 和 `Location` 头
- 浏览器重试受保护的 URL，`auth_inline` 验证 Cookie，消耗一次性的 Token ID，返回允许

**完整步骤序列：**
1. 客户端向 Nginx 请求 `GET /releases/file.iso`
2. Nginx 发送内部子请求到 `/auth/inline`，代理到网关 `/api/auth_inline`
3. 网关评估白名单、黑名单、策略规则和 Cookie 状态
4. 网关返回：`200`、`401`（`X-Auth-Action: challenge`）、`403`、`302`（`Location`）、`444` 或 `503`
5. 若选择挑战路径，Nginx 设置 `pow_target=<编码的原始URL>` Cookie 并重定向用户到挑战页面
6. 浏览器获取 `/api/challenge`，收到签名挑战前缀和难度
7. 浏览器解决 PoW 并以表单或 JSON 形式提交 `/api/verify_pow`
8. 网关验证提交，设置一次性 `auth_token` Cookie，重定向到目标
9. 浏览器使用 `auth_token` 重试原始 URL，网关验证绑定和一次性消费，然后允许请求

## 端点一览

| 方法   | 路径                 | 用途                              | 需要认证              |
|--------|----------------------|-----------------------------------|---------------------|
| GET    | `/api/auth_inline`   | Nginx `auth_request` 认证决策端点   | Nginx 内部子请求上下文 |
| GET    | `/api/challenge`      | 为浏览器流程生成 PoW 挑战           | 无需先前的 auth Cookie |
| POST   | `/api/verify_pow`     | 验证 PoW 提交并颁发一次性 auth Cookie | 需要有效的挑战解决方案   |
| GET    | `/healthz`            | 存活探针端点                        | 否                  |
| GET    | `/metrics`            | Prometheus 指标端点                 | 否                  |

## 常用请求头

| 头字段              | 使用端点                                  | 必需   | 用途                                                      | 示例值                                        |
|---------------------|------------------------------------------|--------|-----------------------------------------------------------|----------------------------------------------|
| `X-Real-IP`         | `/api/auth_inline`, `/api/challenge`, `/api/verify_pow` | 是     | 客户端 IP，用于子网密钥、策略决策和子网绑定                  | `192.0.2.1`                                 |
| `X-URL`             | `/api/auth_inline`, `/api/challenge`               | 预期（auth_inline），条件（challenge 通过 `pow_target` 回退） | 正在授权/挑战的完整目标 URL                            | `https://mirror.example.com/releases/file.iso` |
| `X-UA`              | `/api/auth_inline`, `/api/challenge`, `/api/verify_pow` | 可选   | User-Agent，用于客户端分类和 Cookie UA 摘要绑定              | `Mozilla/5.0 (X11; Linux x86_64)`           |
| `X-Request-ID`      | `/api/auth_inline`                                  | 可选   | 请求关联 ID，缺失时自动生成                                  | `req-7f9c2d4a`                              |
| `X-Forwarded-Host`  | `/api/auth_inline`                                  | 可选   | 策略路由评估的首选主机上下文                                   | `mirror.example.com`                        |
| `X-Host`            | `/api/auth_inline`                                  | 可选   | `X-Forwarded-Host` 缺失时的备用主机                          | `mirror.example.com`                        |
| `X-JA3-Hash`        | `/api/auth_inline`                                  | 可选   | TLS 指纹遥测，用于分类和日志                                 | `d41d8cd98f00b204e9800998ecf8427e`          |
| `Cookie`            | 所有端点                                            | 可选   | 携带 `auth_token`（内联认证）和 `pow_target`（挑战回退目标）   | `auth_token=<token>; pow_target=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso` |

## Cookie 语义

Cookie 行为来自 `internal/cookie` 和管道验证。

**auth_token Cookie：**
- **名称**：`auth_token`
- **格式**：base64url 编码的有效载荷 + HMAC-SHA256 签名
- **TTL**：默认 15 秒（`Max-Age=15`）
- **一次性使用**：Token ID 通过 `CookieConsumptionStore` 消耗一次；重放尝试失败
- **验证时检查的绑定**：
  - 客户端 IP 的子网密钥（IPv4 /24，IPv6 /56 via `subnet.DefaultKey`）
  - `X-UA` 的 UA 摘要（SHA-256，前 16 字节十六进制）
  - 规范化的目标路径（剥离查询参数）
- **Set-Cookie 安全标志**：
  - `Path=/`
  - `HttpOnly`
  - `Secure`
  - `SameSite=Lax`
  - `Max-Age=15`（默认）

**pow_target Cookie：**
- Nginx 挑战重定向设置 `pow_target=<url编码目标>; Path=/; SameSite=Lax`
- `/api/challenge` 仅在 `X-URL` 头缺失时使用此 Cookie 作为回退
- `pow_target` 是挑战辅助 Cookie，不是认证 Cookie

## 错误分类

| 端点               | HTTP 状态 | 错误码/响应体                              | 含义                              |
|-------------------|-----------|------------------------------------------|----------------------------------|
| `/api/auth_inline` | `200`     | 无                                       | 被白名单放行、有效 Cookie、允许规则或在配额下直接签章 |
| `/api/auth_inline` | `401`     | 头 `X-Auth-Action: challenge`             | 需要浏览器挑战                       |
| `/api/auth_inline` | `403`     | 无                                       | 被黑名单拒绝、拒绝规则或配额超限且无重定向 URL   |
| `/api/auth_inline` | `302`     | `Location` 头                            | 重定向规则，或配额超限且配置了重定向 URL       |
| `/api/auth_inline` | `444`     | 无                                       | 丢弃规则，Nginx 特定连接关闭状态          |
| `/api/auth_inline` | `503`     | 无                                       | 配额检查期间 panic 恢复或状态不可用        |
| `/api/challenge`   | `400`     | `invalid client ip`                      | 缺失或无法解析的客户端 IP 用于子网密钥      |
| `/api/challenge`   | `400`     | `missing X-URL header`                   | 无 `X-URL` 头且无 `pow_target` 回退 Cookie |
| `/api/challenge`   | `405`     | `method not allowed`                     | 方法必须是 `GET`；包含 `Allow: GET`    |
| `/api/challenge`   | `500`     | `internal server error`                  | 盐生成失败                          |
| `/api/verify_pow`  | `400`     | `{"error":"missing required fields"}`    | 表单或 JSON 体中缺失 `prefix` 或 `nonce`   |
| `/api/verify_pow`  | `403`     | `{"error":"invalid or expired prefix"}`  | 前缀签名不匹配、前缀格式错误或前缀过期          |
| `/api/verify_pow`  | `403`     | `{"error":"subnet mismatch"}`            | 请求子网与前缀嵌入的子网不匹配              |
| `/api/verify_pow`  | `403`     | `{"error":"invalid proof of work difficulty"}` | 配置难度边界无效或计算难度 <= 0        |
| `/api/verify_pow`  | `403`     | `{"error":"invalid proof of work"}`      | Nonce 不满足前导零难度要求              |
| `/api/verify_pow`  | `403`     | `{"error":"replay detected"}`            | Nonce 已在 nonce 存储中被见过            |
| `/api/verify_pow`  | `405`     | `method not allowed`                     | 方法必须是 `POST`；包含 `Allow: POST`   |
| `/api/verify_pow`  | `503`     | `{"error":"internal state unavailable"}` | 锁定/检查期间 Nonce 存储不可用            |
| `/api/verify_pow`  | `503`     | `internal server error`                  | Cookie 颁发失败                      |

## 端点详情

### GET /api/auth_inline

**用途**：Nginx `auth_request` 决策端点，用于受保护资源请求。

网关与 Nginx 传输的契约：
- 公共契约是 `GET /api/auth_inline`
- Nginx 内部位置 `/auth/inline` 使用 `proxy_method POST` 并代理到 `/api/auth_inline`
- 此端点被视为头驱动的决策 API，不使用请求体

**请求头（消费）**：
- 实践中必需：`X-Real-IP`、`X-URL`
- 可选但存在时使用：`X-UA`、`X-Request-ID`、`X-Forwarded-Host`、`X-Host`、`X-JA3-Hash`、`Cookie`

**响应头（发出）**：
- `401` 时：`X-Auth-Action: challenge`
- `302` 时（有重定向 URL）：`Location: <redirect-url>`

**决策矩阵和状态映射**：

| 顺序 | 检查                              | 结果               | 状态                         |
|-----:|-----------------------------------|-------------------|------------------------------|
|    1 | 子网密钥缺失                        | 挑战回退路径          | `401`（`X-Auth-Action: challenge`） |
|    2 | IP 匹配白名单                       | 立即允许             | `200`                        |
|       3 | IP 匹配黑名单                       | 立即拒绝             | `403`                        |
|    4 | 策略规则 `Reject`                  | 拒绝               | `403`                        |
|    5 | 策略规则 `Redirect`               | 配置时带 `Location` 重定向 | `302`                       |
|    6 | 策略规则 `Drop`                    | 丢弃请求             | `444`                        |
|    7 | 策略规则 `Allow`                  | 允许（仍受配额检查）     | `200`、`302`、`403` 或 `503`     |
|    8 | 有效的一次性 Cookie                 | 允许（配额检查）        | `200`、`302`、`403` 或 `503`     |
|    9 | 浏览器客户端且无有效 Cookie           | 挑战               | `401`（`X-Auth-Action: challenge`） |
|   10 | 非浏览器且无有效 Cookie              | 直接签章然后允许（配额检查） | `200`、`302`、`403` 或 `503`     |

配额交互（允许路径）：
- 对于 `ActionAccept` 和 `ActionDirectSign`，网关按子网增加配额
- 若配额存储不可用，网关返回 `503`
- 若超过配额且配置了重定向 URL，网关返回带 `Location` 的 `302`
- 若超过配额且无重定向 URL，网关返回 `403`

**Nginx `auth_request` 集成示例**：

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

**请求示例**：

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

**响应变体**：

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

---

### GET /api/challenge

**用途**：为调用者子网和目标 URL 生成 PoW 挑战。

**方法**：仅接受 `GET`

**必需头**：
- `X-Real-IP`：必需，用于派生子网密钥
- `X-URL`：条件必需；如缺失，使用 `pow_target` Cookie 作为回退（见下文目标解析顺序）

**可选头**：
- `X-UA`：接受并转发，挑战生成不需要

**目标 URL 解析顺序**：
1. 若存在，使用 `X-URL` 头
2. 若缺失，读取 `pow_target` Cookie 并 URL 解码
3. 若仍缺失，返回 `400`（`missing X-URL header`）

**成功响应**（`200 application/json`）：
- `prefix`：签名挑战字符串（包含目标、子网密钥、时间戳、盐、HMAC）
- `difficulty`：PoW 验证所需的前导零位数/字符数
- `target`：此挑战解决后授权的目标 URL

**请求示例**：

```http
GET /api/challenge HTTP/1.1
Host: mirror.example.com
X-Real-IP: 192.0.2.44
X-URL: https://mirror.example.com/releases/file.iso
X-UA: Mozilla/5.0 (X11; Linux x86_64)
```

**使用 Cookie 回退的请求示例**：

```http
GET /api/challenge HTTP/1.1
Host: mirror.example.com
X-Real-IP: 192.0.2.44
Cookie: pow_target=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso
```

**成功响应示例**：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"prefix":"https://mirror.example.com/releases/file.iso|192.0.2.0/24|1713345600|f6c9a13d6bf2a9fe7db1e04c4dce11aa|4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2","difficulty":6,"target":"https://mirror.example.com/releases/file.iso"}
```

**错误响应**：

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

---

### POST /api/verify_pow

**用途**：验证 PoW 提交，颁发短命的一次性 auth Cookie，并重定向到目标。

**方法**：仅接受 `POST`

**接受的请求体格式**：
1. 表单请求体（`application/x-www-form-urlencoded` 或 multipart，由 `ParseForm` 解析）
   - `prefix`（必需）
   - `nonce`（必需）
   - `target_uri`（可选）
2. JSON 请求体（`application/json`）
   - `prefix`（必需）
   - `nonce`（必需）
   - `target_uri`（可选）

**OpenAPI 表示说明**：生成的 OpenAPI 规范仅建模 JSON 请求体格式。运行时也接受相同字段名（`prefix`、`nonce`、`target_uri`）的 `application/x-www-form-urlencoded` 表单提交，但这种双格式支持无法在 Swagger 2.0 中清晰表达。集成方应优先使用 JSON；表单提交仅用于浏览器兼容性支持。

**必需头**：
- `X-Real-IP`（子网验证必需）

**可选头**：
- `X-UA`（用于绑定颁发的 Cookie）

**验证链**：
1. 解析提交并确保 `prefix` 和 `nonce` 存在
2. 验证签名前缀完整性和 TTL
3. 验证请求子网等于前缀嵌入的子网
4. 计算并验证当前 PoW 难度边界
5. 验证 PoW（`sha256(prefix + nonce)` 具有所需的前导零）
6. 在重放存储中检查并锁定 nonce
7. 从请求值或前缀目标解析 `target_uri`
8. 颁发绑定到子网、UA 摘要和规范目标路径的 `auth_token` Cookie
9. 返回带 `Location` 和 `Set-Cookie` 的 `302`

**成功响应**：
- 状态：`302 Found`
- 头：
  - `Location: <target_uri>`
  - `Set-Cookie: auth_token=...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=15`

**请求示例（表单）**：

```http
POST /api/verify_pow HTTP/1.1
Host: mirror.example.com
Content-Type: application/x-www-form-urlencoded
X-Real-IP: 192.0.2.44
X-UA: Mozilla/5.0 (X11; Linux x86_64)

prefix=https%3A%2F%2Fmirror.example.com%2Freleases%2Ffile.iso%7C192.0.2.0%2F24%7C1713345600%7Cf6c9a13d6bf2a9fe7db1e04c4dce11aa%7C4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2&nonce=0000006ab9f&target_uri=%2Freleases%2Ffile.iso
```

**请求示例（JSON）**：

```http
POST /api/verify_pow HTTP/1.1
Host: mirror.example.com
Content-Type: application/json
X-Real-IP: 192.0.2.44
X-UA: Mozilla/5.0 (X11; Linux x86_64)

{"prefix":"https://mirror.example.com/releases/file.iso|192.0.2.0/24|1713345600|f6c9a13d6bf2a9fe7db1e04c4dce11aa|4a8d3d4b9fb9dc3316f16b301c5f4e7a1b2ef8e0ef1e93a1f4f8e58f26fbf1a2","nonce":"0000006ab9f","target_uri":"/releases/file.iso"}
```

**成功响应示例**：

```http
HTTP/1.1 302 Found
Location: /releases/file.iso
Set-Cookie: auth_token=ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbXRwWkNJNkltTnZiU0o5...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=15
```

**错误响应**：

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

---

### GET /healthz

**用途**：运维存活端点。

**响应**：
- `200 OK`
- 响应体：`ok`

**运维说明**：此端点仅用于运维，被排除在 OpenAPI 契约之外。

---

### GET /metrics

**用途**：Prometheus 指标端点，用于运维。

**响应**：
- `200 OK`，Prometheus 文本展示格式

**运维说明**：此端点仅用于运维，被排除在公共 OpenAPI 规范之外。

---

## 运维端点

`/healthz` 和 `/metrics` 是运维端点。它们有意被排除在公共 OpenAPI 规范之外，仅用于面向客户端的认证集成。

## OpenAPI 规范重新生成

重新生成 OpenAPI 产物：

```bash
./scripts/openapi.sh
```

**注意**：
- 此脚本运行 `swag init` 并将生成的文件写入 `docs/openapi`
- 请保持 `docs/api.md` 作为生成 OpenAPI 产物的可读契约伴随文档
