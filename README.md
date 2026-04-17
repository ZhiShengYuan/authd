# mirror-auth-backend

## 项目简介

`mirror-auth-backend` 是一个面向内部服务的轻量 JSON 网关，提供两类核心能力：

1. 挑战 challenge 的配置与一次性 PoW 验证
2. 票据 ticket 的签发与多次验证（按次消耗）

服务定位是内部可信网络中的认证前置组件，用统一的 HTTP JSON 接口承载挑战与票据的生命周期管理。所有业务响应都使用统一 envelope 格式：

```json
{
  "success": true,
  "data": {},
  "error": null
}
```

失败时：

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "..."
  }
}
```

> 说明：本服务是内部接口，假设调用方与网络环境受控。

## 架构概览

### 包结构

```text
cmd/auth-gateway/main.go                # 进程入口、配置加载、路由装配、优雅退出
internal/api/                           # API 路径常量、请求响应类型、错误码、envelope
internal/config/                        # 配置结构、默认值、校验
internal/handler/                       # 4 个核心接口处理器
internal/pow/                           # PoW 校验、prefix 生成与完整性校验
internal/state/                         # Challenge 内存状态存储与清理
internal/ticket/                        # Ticket 签发、验证、状态管理与清理
internal/observability/                 # 指标暴露（/metrics）
configs/config.example.json             # 示例配置
scripts/race.sh, scripts/coverage.sh    # 测试辅助脚本
```

### 运行时组件关系

```text
HTTP 调用方
   |
   v
auth-gateway (net/http ServeMux)
   |-- /api/challenges ---------> ChallengeConfigHandler -----> state.ChallengeStore
   |-- /api/challenges/verify --> ChallengeVerifyHandler -----> state.ChallengeStore + pow
   |-- /api/tickets ------------> TicketIssueHandler ---------> ticket.TicketManager
   |-- /api/tickets/verify -----> TicketVerifyHandler --------> ticket.TicketManager
   |-- /healthz ----------------> 健康检查
   |-- /metrics ----------------> Prometheus 指标
```

## 快速开始

### 1) 准备配置

复制示例配置并修改：

```bash
cp ./configs/config.example.json ./configs/config.local.json
```

至少保证：

- `security.global_secret` 长度不少于 32 字节
- `server.listen_address` 已设置

### 2) 构建

```bash
go build -o auth-gateway ./cmd/auth-gateway
```

### 3) 启动

```bash
./auth-gateway -config ./configs/config.local.json
```

默认入口参数：

- `-config`，默认值 `./configs/config.example.json`

### 4) 健康与指标

```bash
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/metrics
```

## 配置说明

### 配置文件完整格式

```json
{
  "server": {
    "listen_network": "tcp",
    "listen_address": "127.0.0.1:8080"
  },
  "security": {
    "global_secret": "0123456789abcdef0123456789abcdef",
    "cookie_name": "auth_token",
    "cookie_ttl_seconds": 15,
    "nonce_ttl_seconds": 30,
    "pow_min_difficulty": 4,
    "pow_max_difficulty": 10,
    "challenge_ttl_seconds": 30,
    "ticket_ttl_seconds": 300
  }
}
```

### 字段说明与默认值

### server

| 字段 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `listen_network` | string | 否 | `tcp` | 监听网络，常用 `tcp` 或 `unix` |
| `listen_address` | string | 是 | 无 | 监听地址，如 `127.0.0.1:8080` 或 unix socket 路径 |

### security

| 字段 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `global_secret` | string | 是 | 无 | 全局密钥，长度必须 >= 32 字节 |
| `cookie_name` | string | 否 | `auth_token` | 历史字段，当前挑战, 票据主流程未直接使用 |
| `cookie_ttl_seconds` | int | 否 | `15` | 历史字段，配置加载时仍校验 > 0 |
| `nonce_ttl_seconds` | int | 否 | `30` | 历史字段，配置加载时仍校验 > 0 |
| `pow_min_difficulty` | int | 否 | `4` | 历史字段，配置加载时仍校验 > 0 |
| `pow_max_difficulty` | int | 否 | `10` | 历史字段，必须 >= `pow_min_difficulty` |
| `challenge_ttl_seconds` | int | 否 | `30` | 挑战过期秒数 |
| `ticket_ttl_seconds` | int | 否 | `300` | 票据过期秒数 |

> 注意：`configs/config.example.json` 里的 `pow_window_seconds` 与 `policy` 在当前 `Config` 结构体中未声明，Go JSON 反序列化会忽略这些未知字段。

## API 接口规范

### 通用约定

- 基础 URL 示例：`http://127.0.0.1:8080`
- 请求头：`Content-Type: application/json`
- 所有响应均为 envelope：`success`, `data`, `error`

---

## 1) 配置挑战

- **请求方法**: `POST`
- **路径**: `/api/challenges`

### 请求格式

```json
{
  "challenge_id": "ch_001",
  "difficulty": 4,
  "bind_matrix": {
    "url": "https://example.internal/login",
    "ip": "10.0.0.8",
    "ua": "Mozilla/5.0 ..."
  }
}
```

字段说明：

| 字段 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- |
| `challenge_id` | string | 是 | 去除空白后不能为空 |
| `difficulty` | int | 是 | `>= 1` |
| `bind_matrix.url` | string | 是 | 去除空白后不能为空 |
| `bind_matrix.ip` | string | 是 | 去除空白后不能为空 |
| `bind_matrix.ua` | string | 是 | 去除空白后不能为空 |

### 响应格式

成功 `201 Created`：

```json
{
  "success": true,
  "data": {
    "prefix": "<signed_prefix>",
    "difficulty": 4,
    "challenge_id": "ch_001"
  },
  "error": null
}
```

失败 `400 Bad Request` 或 `405 Method Not Allowed`：

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "..."
  }
}
```

### 请求示例

```bash
curl -X POST http://127.0.0.1:8080/api/challenges \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "ch_001",
    "difficulty": 4,
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    }
  }'
```

### 成功响应示例

```json
{
  "success": true,
  "data": {
    "prefix": "63685f3030313a34|f4d66f1e2f0f...|1710000000|34|a447...",
    "difficulty": 4,
    "challenge_id": "ch_001"
  },
  "error": null
}
```

### 错误响应示例

1. `400 invalid_request`（JSON 非法）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "invalid json payload"
  }
}
```

2. `400 invalid_request`（字段缺失）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "bind_matrix.url, bind_matrix.ip, and bind_matrix.ua are required"
  }
}
```

3. `400 invalid_request`（challenge 重复配置等存储失败）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "failed to configure challenge"
  }
}
```

4. `405 invalid_request`（方法错误）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "method not allowed"
  }
}
```

---

## 2) 验证挑战

- **请求方法**: `POST`
- **路径**: `/api/challenges/verify`

### 请求格式

```json
{
  "challenge_id": "ch_001",
  "nonce": "123456",
  "prefix": "63685f3030313a34|f4d66f1e2f0f...|1710000000|34|a447..."
}
```

字段说明：

| 字段 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- |
| `challenge_id` | string | 是 | 去除空白后不能为空 |
| `nonce` | string | 是 | 去除空白后不能为空 |
| `prefix` | string | 是 | 去除空白后不能为空，且必须可通过服务端密钥完整性校验 |

### 响应格式

成功 `200 OK`：

```json
{
  "success": true,
  "data": {
    "valid": true
  },
  "error": null
}
```

失败状态与 envelope：

- `400`: `invalid_request` 或 `challenge_invalid`
- `404`: `challenge_not_found`
- `409`: `challenge_replayed`
- `410`: `challenge_expired`
- `405`: `invalid_request`（方法错误）

### 请求示例

```bash
curl -X POST http://127.0.0.1:8080/api/challenges/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "ch_001",
    "nonce": "123456",
    "prefix": "63685f3030313a34|f4d66f1e2f0f...|1710000000|34|a447..."
  }'
```

### 成功响应示例

```json
{
  "success": true,
  "data": {
    "valid": true
  },
  "error": null
}
```

### 错误响应示例

1. `400 invalid_request`（字段缺失）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "challenge_id, nonce, and prefix are required"
  }
}
```

2. `404 challenge_not_found`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "challenge_not_found",
    "message": "challenge not found"
  }
}
```

3. `410 challenge_expired`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "challenge_expired",
    "message": "challenge expired"
  }
}
```

4. `409 challenge_replayed`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "challenge_replayed",
    "message": "challenge already used"
  }
}
```

5. `400 challenge_invalid`（签名, payload, bind_matrix, nonce 任一不匹配）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "challenge_invalid",
    "message": "challenge verification failed"
  }
}
```

6. `405 invalid_request`（方法错误）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "method not allowed"
  }
}
```

---

## 3) 签发票据

- **请求方法**: `POST`
- **路径**: `/api/tickets`

### 请求格式

```json
{
  "bind_matrix": {
    "url": "https://example.internal/login",
    "ip": "10.0.0.8",
    "ua": "Mozilla/5.0"
  },
  "uses": 3
}
```

字段说明：

| 字段 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- |
| `bind_matrix.url` | string | 是 | 非空 |
| `bind_matrix.ip` | string | 是 | 非空 |
| `bind_matrix.ua` | string | 是 | 非空 |
| `uses` | int | 是 | `>= 1` |

### 响应格式

成功 `201 Created`：

```json
{
  "success": true,
  "data": {
    "ticket": "<base64url_ticket>"
  },
  "error": null
}
```

失败状态与 envelope：

- `400`: `invalid_request` 或 `ticket_exhausted`
- `405`: `invalid_request`（方法错误）

### 请求示例

```bash
curl -X POST http://127.0.0.1:8080/api/tickets \
  -H 'Content-Type: application/json' \
  -d '{
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    },
    "uses": 3
  }'
```

### 成功响应示例

```json
{
  "success": true,
  "data": {
    "ticket": "aHR0cHM6Ly9leGFtcGxlLmludGVybmFsL2xvZ2lufDEwLjAuMC44fGQx..."
  },
  "error": null
}
```

### 错误响应示例

1. `400 invalid_request`（JSON 非法）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "invalid JSON body"
  }
}
```

2. `400 invalid_request`（字段缺失或 uses 非法）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "uses must be at least 1"
  }
}
```

3. `400 ticket_exhausted`（签发失败，例如 manager 不可用）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ticket_exhausted",
    "message": "failed to issue ticket"
  }
}
```

4. `405 invalid_request`（方法错误）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "method not allowed"
  }
}
```

---

## 4) 验证票据

- **请求方法**: `POST`
- **路径**: `/api/tickets/verify`

### 请求格式

```json
{
  "ticket": "<base64url_ticket>",
  "bind_matrix": {
    "url": "https://example.internal/login",
    "ip": "10.0.0.8",
    "ua": "Mozilla/5.0"
  }
}
```

字段说明：

| 字段 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- |
| `ticket` | string | 是 | 非空 |
| `bind_matrix.url` | string | 是 | 非空 |
| `bind_matrix.ip` | string | 是 | 非空 |
| `bind_matrix.ua` | string | 是 | 非空 |

### 响应格式

成功 `200 OK`，注意可能 `valid=true` 或 `valid=false`：

```json
{
  "success": true,
  "data": {
    "valid": true
  },
  "error": null
}
```

绑定矩阵不匹配时返回：

```json
{
  "success": true,
  "data": {
    "valid": false
  },
  "error": null
}
```

失败状态与 envelope：

- `400`: `invalid_request` 或 `ticket_invalid`
- `404`: `ticket_not_found`
- `410`: `ticket_expired` 或 `ticket_exhausted`
- `405`: `invalid_request`（方法错误）

### 请求示例

```bash
curl -X POST http://127.0.0.1:8080/api/tickets/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "ticket": "aHR0cHM6Ly9leGFtcGxlLmludGVybmFsL2xvZ2lufDEwLjAuMC44fGQx...",
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    }
  }'
```

### 成功响应示例

```json
{
  "success": true,
  "data": {
    "valid": true
  },
  "error": null
}
```

### 错误响应示例

1. `400 invalid_request`（字段缺失）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "ticket is required"
  }
}
```

2. `400 ticket_invalid`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ticket_invalid",
    "message": "ticket is invalid"
  }
}
```

3. `404 ticket_not_found`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ticket_not_found",
    "message": "ticket not found"
  }
}
```

4. `410 ticket_expired`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ticket_expired",
    "message": "ticket expired"
  }
}
```

5. `410 ticket_exhausted`

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ticket_exhausted",
    "message": "ticket exhausted"
  }
}
```

6. `405 invalid_request`（方法错误）

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "invalid_request",
    "message": "method not allowed"
  }
}
```

## 完整调用流程

以下示例展示一次典型链路，从挑战配置到票据验证。

### 第 1 步：配置挑战

```bash
curl -sS -X POST http://127.0.0.1:8080/api/challenges \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "ch_flow_001",
    "difficulty": 4,
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    }
  }'
```

从返回中提取 `data.prefix` 和 `data.difficulty`。

### 第 2 步：客户端求解 PoW

目标是找到一个 `nonce`，使：

```text
SHA256(prefix + nonce)
```

具备足够前导零位。按当前实现，判定规则是十六进制字符串前 `difficulty` 个字符为 `0`。

### 第 3 步：验证挑战（单次）

```bash
curl -sS -X POST http://127.0.0.1:8080/api/challenges/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge_id": "ch_flow_001",
    "nonce": "<pow_nonce>",
    "prefix": "<prefix_from_step1>"
  }'
```

> 注意：挑战在验证入口会先 `consume`，同一个 `challenge_id` 再次提交会得到 `409 challenge_replayed`。

### 第 4 步：签发票据

```bash
curl -sS -X POST http://127.0.0.1:8080/api/tickets \
  -H 'Content-Type: application/json' \
  -d '{
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    },
    "uses": 3
  }'
```

从返回中提取 `data.ticket`。

### 第 5 步：验证票据（可多次，直到耗尽）

```bash
curl -sS -X POST http://127.0.0.1:8080/api/tickets/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "ticket": "<ticket_from_step4>",
    "bind_matrix": {
      "url": "https://example.internal/login",
      "ip": "10.0.0.8",
      "ua": "Mozilla/5.0"
    }
  }'
```

重复调用将持续消耗次数，直至返回 `410 ticket_exhausted`。

## PoW 求解说明

### prefix 包含内容

服务端返回的 `prefix` 由以下 5 段拼接：

```text
targetURI | subnetKey | timestamp | saltHex | signatureHex
```

- `targetURI`：内部是 `hex(challenge_id) + ":" + difficulty`
- `subnetKey`：`sha256(url + "|" + ip + "|" + ua)` 的十六进制值
- `timestamp`：秒级时间戳
- `saltHex`：`difficulty` 的十六进制表示（来自 `strconv.Itoa(difficulty)`）
- `signatureHex`：对前四段用 HMAC-SHA256 计算得到

客户端不需要解析这些字段，只需要使用完整 `prefix` 参与哈希求解。

### 如何找 nonce

1. 固定服务端返回的 `prefix`
2. 从某个起点开始递增 nonce，例如 `0, 1, 2...`
3. 计算 `sha256(prefix + nonce)`
4. 转成十六进制字符串，检查前缀是否有 `difficulty` 个 `0`
5. 命中后将 nonce 提交到 `/api/challenges/verify`

> 当前实现按十六进制字符前导零判定，不是按二进制位逐位判定。若 `difficulty=4`，等价于前 16 个二进制位为 0。

### Python 示例求解器

```python
import hashlib

def solve_pow(prefix: str, difficulty: int, start: int = 0):
    target = "0" * difficulty
    n = start
    while True:
        nonce = str(n)
        digest = hashlib.sha256((prefix + nonce).encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return nonce, digest
        n += 1


if __name__ == "__main__":
    prefix = "<prefix_from_api>"
    difficulty = 4
    nonce, digest = solve_pow(prefix, difficulty)
    print("nonce:", nonce)
    print("hash :", digest)
```

## 错误码参考

以下为 `internal/api/errors.go` 中定义的全部错误码。

| 错误码 | 典型 HTTP 状态 | 含义 | 触发条件 |
| --- | --- | --- | --- |
| `invalid_request` | 400, 405 | 请求不合法 | JSON 解析失败, 方法错误, 必填字段缺失, 参数非法 |
| `challenge_not_found` | 404 | 挑战不存在 | 验证时找不到对应 `challenge_id` |
| `challenge_expired` | 410 | 挑战已过期 | 超过 `challenge_ttl_seconds` |
| `challenge_replayed` | 409 | 挑战已被使用 | 同一 `challenge_id` 重放验证 |
| `challenge_invalid` | 400 | 挑战校验失败 | prefix 签名失效, payload 不匹配, bind 不匹配, nonce 无效 |
| `ticket_not_found` | 404 | 票据不存在 | 票据状态未找到（例如已清理） |
| `ticket_expired` | 410 | 票据已过期 | 超过 `ticket_ttl_seconds` |
| `ticket_exhausted` | 410（验证时）/ 400（签发失败时） | 票据次数耗尽 | 验证扣减后次数小于 0，或签发路径内部失败 |
| `ticket_invalid` | 400 | 票据格式或签名无效 | base64 非法, 结构非法, HMAC 校验失败等 |

## 设计决策

### 为什么每次验证都消耗使用次数

`TicketManager.Verify` 在读取票据状态后先执行 `remainingUses.Add(-1)`，再判断过期与绑定匹配。这样可以把每一次验证尝试都视为一次资源消耗，降低穷举绑定信息和重复探测的收益。

### 为什么挑战只能验证一次

`ChallengeStore.Consume` 使用原子 CAS 将 `Consumed` 从 `false` 改为 `true`。一旦成功消费，再次验证会命中 `challenge_replayed`。这能直接阻断 replay。

### 为什么 TTL 由服务端控制

挑战与票据的 TTL 分别来自 `challenge_ttl_seconds` 和 `ticket_ttl_seconds`，客户端无法覆盖。统一由服务端掌控时效窗口，行为一致，审计简单。

### 为什么 bind_matrix 使用结构化 JSON

`bind_matrix` 固定为 `url`, `ip`, `ua` 三字段。结构化字段便于服务端做稳定拼接与哈希，也方便未来对单字段扩展校验。

### 内部服务信任假设

该服务面向内部调用，默认调用方身份与网络边界已由上游系统约束。接口仍做基础参数检查与签名校验，但不承担公网零信任场景下的全部防护职责。

## 测试与验证

### 运行全部测试

```bash
go test ./...
```

### 覆盖率

```bash
./scripts/coverage.sh
```

### 竞态检测

```bash
./scripts/race.sh
```

### 可选：单模块验证

```bash
go test ./internal/handler/... ./internal/ticket/... ./internal/state/... ./internal/pow/...
```

以上命令可用于发布前回归，重点覆盖挑战, 票据的时效与并发行为。
