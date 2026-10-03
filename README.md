# Request Integrity & Anti-Replay Layer

在保持既有接口行为不变的前提下（`GET /` 不受影响），为受保护端点
（如 `POST /api/echo`）增加了请求完整性校验与防重放能力。

## 请求签名方式

调用方对请求计算 HMAC-SHA256 签名，并通过头部携带：

| Header        | 含义                                   |
|---------------|----------------------------------------|
| `X-Caller-Id` | 调用方标识                             |
| `X-Scope`     | 本次调用的作用域                       |
| `X-Key-Id`    | 签名密钥 ID（kid）                     |
| `X-Timestamp` | Unix 秒时间戳                          |
| `X-Nonce`     | 一次性随机串                           |
| `X-Signature` | 64 位十六进制 HMAC-SHA256              |

### 规范化（canonicalization）

签名前将请求按固定规则规范化，保证内容相同必得相同摘要、任一字段改动
必得不同摘要：

```
METHOD\nPATH\nSORTED_QUERY\nTIMESTAMP\nNONCE\nSHA256HEX(BODY)
```

- `METHOD` 大写；查询参数解码后按 `k=v` 排序，与参数顺序无关；
- body 先取 SHA-256，签名串长度恒定，单字节改动即改变摘要。

## 校验流水线与拒绝原因

校验按固定顺序执行，每种失败有可区分的机器可读原因码
（HTTP 响应体 `detail` 字段），且全部写入审计日志（不含密钥材料）：

| 顺序 | 检查       | 原因码               | HTTP |
|------|-----------|----------------------|------|
| 1    | 结构       | `malformed_request`  | 400  |
| 2    | 时间戳过旧 | `timestamp_expired`  | 401  |
| 2    | 时间戳超前 | `timestamp_skew`     | 401  |
| 3    | 未知密钥   | `key_unknown`        | 401  |
| 3    | 已停用密钥 | `key_revoked`        | 401  |
| 4    | 签名不符   | `signature_invalid`  | 401  |
| 5    | 越权作用域 | `forbidden_scope`    | 403  |
| 6    | 重放       | `replay_detected`    | 409  |

- **完整性**：任何字段（方法、路径、查询、时间戳、nonce、body）被篡改
  都会使签名校验失败，以 `signature_invalid` 拒绝。
- **防重放**：对规范化内容摘要做原子 check-and-record，窗口内同一请求
  仅第一次被接受；并发下同一请求至多一个通过（互斥判定）。
- **时钟**：时间戳超出容忍窗口（过旧/超前）即拒绝；重放记录使用
  单调时钟（`time.monotonic`），本地时钟回拨或漂移不会重放窗口。
- **清理**：过期记录随窗口推进被清理，长时间运行内存有界；清理只删除
  已过期记录，不会误删窗口内记录。
- **健壮性**：超大 body、非法编码、缺字段、非法签名格式均稳定拒绝，
  不向调用方泄露内部异常细节。

## 密钥轮换

多个密钥按代次（generation）并存：最高代次为 ACTIVE（签名用），其余
未停用密钥为 RETIRED（轮换期内仍可校验旧签名），被停用的密钥一律拒绝。
密钥材料不会出现在日志、异常信息或 HTTP 响应中。

## 配置项

通过环境变量配置（见 `app/guard.py: settings_from_env`）：

| 环境变量                          | 默认   | 说明                         |
|-----------------------------------|--------|------------------------------|
| `INTEGRITY_KEY_IDS`               | —      | 逗号分隔的 kid 列表          |
| `INTEGRITY_KEY_<KID>`             | —      | 对应 kid 的密钥材料          |
| `INTEGRITY_KEYGEN_<KID>`          | 0      | 对应 kid 的代次              |
| `INTEGRITY_REVOKED_KIDS`          | —      | 逗号分隔的已停用 kid         |
| `INTEGRITY_CALLER_SCOPES`         | —      | `caller:scope1\|scope2,...`  |
| `INTEGRITY_TOLERANCE_SECONDS`     | 300    | 时间戳容忍窗口               |
| `INTEGRITY_REPLAY_WINDOW_SECONDS` | 600    | 重放记录保留窗口             |
| `INTEGRITY_MAX_BODY_BYTES`        | 1048576| 请求体大小上限               |

也可直接构造 `app.config.Settings` 并调用 `app.guard.build_verifier(settings)`。

## 测试

```bash
uv run pytest tests/ -q
```

覆盖：内容篡改、重复重放、并发重复（64 线程仅 1 个通过）、时钟偏移/
回拨、密钥轮换（新旧可验、停用/未知被拒）、记录清理与内存有界、
畸形输入与 HTTP 层端到端行为。
