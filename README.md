# request-integrity-python

一个基于 FastAPI 的请求完整性校验与防重放服务。在业务接口之前叠加一层
HMAC 签名校验、时间戳窗口、防重放与调用方作用域控制，确保请求在传输过程中
未被篡改、且不会被原样重放。

## 功能特性

- **内容完整性**：按固定规范化规则对请求方法、路径、查询串、头域、请求体
  计算摘要并校验，任一字段被篡改都会被拒绝。
- **防重放**：基于请求指纹的窗口内去重，同一请求只放行第一次。
- **时钟偏移与回拨防护**：时间戳容忍窗口 + 锚定请求时间戳的记录过期策略，
  回拨或漂移都不会误放行重放请求。
- **多密钥轮换**：支持多个校验密钥并存，按代次轮换；轮换期间新旧密钥都可
  验证，已停用或未知密钥被拒绝。
- **作用域控制**：不同调用方只能在其被授予的作用域内调用，越权请求被拒绝。
- **并发互斥**：重放检测在并发下原子判定，同一请求至多放行一次。
- **有界存储**：记录随窗口推进清理，不会无界增长，也不会误删窗口内记录。
- **稳定拒绝**：请求体过大、编码异常、缺字段、签名格式非法等输入被稳定
  拒绝，不泄露内部细节。
- **可追溯审计**：校验通过、失败、越权判定均写入审计日志。

## 快速开始

```bash
# 安装依赖
uv sync

# 运行服务
uv run python main.py

# 运行测试
uv run pytest
```

服务默认监听 `127.0.0.1` 上的随机端口。健康检查 `GET /health` 豁免校验。

## 签名调用示例

```python
from integrity.client import sign_request

headers = sign_request(
    method="GET",
    path="/api/orders",
    caller_id="caller-a",
    key_id="key-2024-02",
    secret=b"current-secret-material",
)
# 携带 headers 发起请求
```

## 文档

完整的校验语义、规范化规则、错误码与配置项说明见
[INTEGRITY.md](./INTEGRITY.md)。

## 项目结构

```
integrity/
  canonical.py    # 规范化规则与 HMAC 签名
  client.py       # 客户端签名辅助
  config.py       # 配置与环境变量
  errors.py       # 类型化错误与原因码
  keys.py         # 密钥注册表与代次轮换
  middleware.py   # ASGI 中间件
  replay.py       # 防重放存储
  scope.py        # 调用方与作用域
  audit.py        # 审计日志
  verifier.py     # 校验编排
main.py           # 服务装配与路由
tests/            # 自动化测试
```
