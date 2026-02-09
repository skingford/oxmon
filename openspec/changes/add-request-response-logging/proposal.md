## Why

oxmon-server 的 REST API 目前缺少统一的请求/响应日志记录。排查线上问题时无法快速定位某次请求的完整链路（请求参数、响应内容、耗时），需要新增结构化的 HTTP 日志中间件并通过唯一 traceId 串联请求与响应。

## What Changes

- 新增 axum 请求/响应日志中间件，记录每次 HTTP 请求的方法、路径、查询参数、状态码、耗时
- 为每个请求生成 16 位唯一 traceId（随机十六进制），贯穿请求-响应日志，便于追踪
- 响应 body 最多打印前 200 个字符，避免大响应体撑爆日志
- 请求日志与响应日志使用不同颜色（通过 tracing 的 level 或自定义前缀区分），提升终端可读性
- traceId 通过 `X-Trace-Id` 响应头返回给客户端，便于前端/调用方反馈问题时提供

## Capabilities

### New Capabilities

- `http-request-logging`: HTTP 请求/响应日志中间件，包含 traceId 生成、请求记录、响应记录（截断）、耗时统计、颜色区分

### Modified Capabilities

（无现有 spec 需要修改）

## Impact

- **代码**: `oxmon-server` crate，新增日志中间件模块，在 `main.rs` 路由构建时加入 layer
- **依赖**: 使用 `rand` crate 生成 traceId（项目已间接依赖）；现有 `tracing` / `tracing-subscriber` 已满足日志输出需求
- **API**: 所有 REST 端点的响应会新增 `X-Trace-Id` header
- **性能**: 响应 body 需要缓冲读取（最多 200 字符），对大多数 JSON 响应影响可忽略
