## Context

oxmon-server 使用 axum 0.8 构建 REST API，当前已有 JWT 认证中间件和 CORS layer，但没有统一的请求/响应日志记录。日志基础设施使用 `tracing` + `tracing-subscriber`（env-filter）。路由分为 public、login、protected、cert 四组，最终合并为一个 `Router`，在 `.layer(cors)` 之前。

## Goals / Non-Goals

**Goals:**
- 为所有 REST API 请求记录结构化日志：方法、路径、查询参数、状态码、耗时
- 每个请求生成 16 位唯一 traceId，串联请求与响应日志
- 响应 body 截断至前 200 字符，避免日志膨胀
- 请求日志（蓝色 `-->` 前缀）与响应日志（绿色/红色 `<--` 前缀）颜色区分
- 通过 `X-Trace-Id` 响应头返回 traceId

**Non-Goals:**
- 不记录请求 body（POST/PUT body 可能包含敏感信息如 token、密码）
- 不记录 gRPC 请求（仅覆盖 HTTP REST API）
- 不做日志持久化/写文件（由 tracing-subscriber 和 PM2 管理）
- 不记录 Swagger UI 静态资源请求

## Decisions

### 1. 中间件实现方式：axum `middleware::from_fn` + 手动 body 缓冲

**选择**: 使用 `axum::middleware::from_fn` 编写自定义中间件函数，手动读取响应 body 并截断。

**备选方案**:
- `tower-http::trace::TraceLayer` — 开箱即用，但无法截取响应 body 内容，也不支持自定义颜色前缀
- `tower` Service trait 手动实现 — 过于复杂，不值得

**理由**: `from_fn` 足够灵活，可以包装 `next.run(request)` 后读取 response body bytes，截取前 200 字符再重新组装 body。代码量适中，维护简单。

### 2. traceId 生成：16 位随机十六进制字符串

**选择**: 使用 `rand` crate 生成 8 字节随机数，编码为 16 位十六进制字符串（如 `a3f1b2c4e5d6f7a8`）。不引入额外依赖，项目已间接依赖 `rand`（通过 `ring`）。

**备选方案**:
- UUID v4（36 字符） — 太长，日志中占位过多，16 位已足够保证唯一性（2^64 碰撞空间）
- 使用项目已有的 Snowflake ID (`oxmon-common::id`) — 纯数字 ID 不够直观，且 Snowflake 面向内部数据
- nanoid — 需要额外 crate

**理由**: 16 位 hex 紧凑且唯一性充足，日志中易于搜索和复制，无需新增依赖。

### 3. 颜色输出方案：ANSI 转义码直接输出

**选择**: 在 `tracing::info!` 宏中嵌入 ANSI 颜色码，请求用蓝色 `\x1b[36m-->` 前缀，成功响应用绿色 `\x1b[32m<--` 前缀，错误响应（4xx/5xx）用红色/黄色 `\x1b[31m<--` 前缀。

**备选方案**:
- 使用 `tracing` 的不同 level（info vs warn）区分 — 会影响日志过滤语义，info/warn 有各自含义
- 使用 `colored` crate — 额外依赖，且 tracing-subscriber 的 fmt 层已支持 ANSI

**理由**: 直接内嵌 ANSI 码最轻量，不引入新依赖。tracing-subscriber fmt 默认启用 ANSI，终端直接渲染颜色。

### 4. 响应 body 截取策略

**选择**: 将 response body 收集为 `Bytes`，转为 UTF-8 字符串后取前 200 字符，然后重新包装为 `Body` 返回给客户端（完整 body 不受影响，日志中截断）。

**注意**: 对于 SSE/流式响应或二进制内容，仅记录 `<body: non-utf8 or streaming>` 而非尝试截取。

### 5. Layer 位置：最外层（CORS 之前）

**选择**: 日志 layer 加在 `cors` layer 之后（即 axum layer 栈中更靠外），确保所有请求（包括 CORS preflight）都被记录。

```
app.layer(request_logging_layer).layer(cors)
```

**理由**: 日志应覆盖所有到达服务器的请求，包括被 CORS 拒绝的。

## Risks / Trade-offs

- **[响应 body 缓冲] → 内存**: 需要将完整响应 body 收集到内存中。对于 oxmon 的 JSON API 响应（通常 < 100KB），这完全可接受。如果未来有大文件下载端点，需要跳过 body 收集。
  - **缓解**: 仅对 `Content-Type: application/json` 的响应做 body 截取，其他类型只记录 `<non-json body>`。

- **[ANSI 颜色码] → 日志文件**: PM2 日志文件中会包含 ANSI 转义序列。
  - **缓解**: 可通过 `RUST_LOG` 或 `NO_COLOR` 环境变量控制；也可以用 `cat -v` 或 `less -R` 查看。这是可接受的 trade-off，终端实时查看时体验优先。

- **[traceId 碰撞]**: 16 位 hex（8 字节随机）碰撞空间为 2^64。
  - **缓解**: 对于单进程 HTTP 服务，碰撞概率极低，完全可接受。
