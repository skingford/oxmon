## Context

当前 oxmon-server 的所有 REST API 接口（25 个）完全公开暴露，无任何鉴权保护。gRPC 侧已有基于 bearer token + bcrypt 的 Agent 认证机制（`AuthInterceptor`），但 REST API 侧（axum 路由）缺乏对应的访问控制。

现有架构要点：
- **路由层**: 使用 `utoipa_axum::OpenApiRouter` 组织路由，已有 CORS 中间件（`tower-http`）
- **状态管理**: `AppState` 通过 `Arc` 共享到所有 handler，当前包含 storage、alert_engine、notifier、agent_registry、cert_store 等
- **配置**: TOML 格式，`ServerConfig` 包含 grpc_port、http_port、alert、notification、cert_check 段
- **存储**: `CertStore` 管理 cert.db（SQLite），已有 `auth` 模块提供 bcrypt hash 和 AES-256-GCM 加密能力
- **依赖**: workspace 已有 `ring`、`hmac`、`sha2`、`base64`、`bcrypt`，尚无 `jsonwebtoken`

## Goals / Non-Goals

**Goals:**
- 所有 REST API（除 health check 和 login）强制 JWT Bearer Token 鉴权
- 提供登录接口，验证用户名密码后签发 JWT
- 服务启动时自动创建可配置的默认管理员帐号
- OpenAPI 文档体现 Bearer Auth security scheme
- 密码使用 bcrypt 安全存储

**Non-Goals:**
- 不实现 RBAC 角色权限体系（当前只需单一管理员角色）
- 不实现 refresh token 机制（token 过期后重新登录）
- 不实现用户注册 API（用户仅通过配置文件或未来扩展管理）
- 不影响 gRPC Agent 认证（两套认证机制独立运行）
- 不实现 token 黑名单/撤销机制

## Decisions

### D1: JWT 库选择 — `jsonwebtoken` crate

**选择**: 使用 `jsonwebtoken` crate 而非手动基于 `hmac`/`ring` 实现。

**理由**: `jsonwebtoken` 是 Rust 生态中最成熟的 JWT 库，API 简洁（`encode`/`decode` 两个函数），内置 claims 验证（exp、iat、nbf），支持 HS256/HS384/HS512/RS256 等多种算法。手动实现容易引入安全漏洞。

**替代方案**: 基于已有的 `hmac` + `sha2` 手动签发 HS256 token。虽可避免新依赖，但需要自行处理 Base64url 编码、claims 验证、时间校验等，增加出错风险。

### D2: 签名算法 — HS256（HMAC-SHA256）

**选择**: 使用对称密钥 HS256 算法。

**理由**: 单服务部署场景下，对称密钥最简单、性能最优。JWT 的签发和验证都在同一个 oxmon-server 进程内完成，不存在多服务共享公钥的需求。密钥可通过配置文件指定或自动生成。

**替代方案**: RS256（RSA）或 ES256（ECDSA）非对称算法。适用于微服务架构中 token 需要被多个服务独立验证的场景，当前不需要。

### D3: 鉴权实现方式 — axum middleware layer

**选择**: 使用 axum 的 `middleware::from_fn_with_state` 作为 layer 应用到受保护路由组。

**理由**: 与现有 CORS layer 模式一致；可以将公开路由（health、login、openapi）和受保护路由分开组装，无需在每个 handler 中重复鉴权逻辑。中间件从 `Authorization` header 提取 token，验证后将用户信息写入 request extensions。

**替代方案**: 使用 axum `FromRequestParts` extractor（如 `AuthUser`）。灵活性更高但需要每个 handler 显式声明参数，遗漏时不会报错，容易产生安全漏洞。

**路由分组结构**:
```
App
├── /api/v1/health              (公开)
├── /api/v1/auth/login          (公开)
├── /v1/openapi.yaml            (公开)
├── /docs                       (公开)
└── /api/v1/*                   (JWT middleware layer)
    ├── /agents
    ├── /agents/whitelist
    ├── /metrics
    ├── /alerts/*
    ├── /certificates/*
    └── /cert-check/*
```

### D4: 用户存储 — 新增 `users` 表于 cert.db

**选择**: 在现有 `cert.db`（由 `CertStore` 管理）中新增 `users` 表。

**理由**: cert.db 已管理 agent_whitelist（另一种凭证存储），职责相近。避免引入新的数据库文件。`CertStore` 已有成熟的 SQLite 连接池和迁移模式。

**表结构**:
```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

遵循项目已有的 `id`(Snowflake) / `created_at` / `updated_at` 统一规范。密码使用 `bcrypt` 存储（复用 `oxmon-storage/src/auth.rs` 中已有的 `hash_token`/`verify_token`）。

### D5: JWT Secret 管理 — 配置文件指定或自动生成

**选择**: 优先从配置文件 `[auth]` 段读取 `jwt_secret`；若未配置，启动时自动生成随机 secret 并仅在日志中提示。

**理由**: 生产环境需要稳定的 secret（重启后已签发的 token 仍有效）；开发环境可不配置，自动生成方便快速启动。

**注意**: 自动生成的 secret 在服务重启后会变化，导致所有已签发 token 失效。配置文件中应明确提示用户在生产环境中设置固定值。

### D6: 默认管理员帐号 — 启动时条件创建

**选择**: 服务启动时检查 `users` 表，若为空则根据配置文件创建默认管理员。

**理由**: 首次部署需要一个初始帐号才能登录。通过配置文件 `[auth]` 段的 `default_username` / `default_password` 指定，不硬编码。

**配置结构**:
```toml
[auth]
jwt_secret = "your-secret-key-here"    # 可选，不设置则自动生成
token_expire_secs = 86400               # 默认 24 小时
default_username = "admin"              # 默认管理员用户名
default_password = "changeme"           # 默认管理员密码
```

### D7: AppState 扩展方式

**选择**: 在 `AppState` 中新增 `jwt_secret: Arc<String>` 和 `token_expire_secs: u64` 字段。

**理由**: JWT 中间件需要访问 secret 进行验证。通过 `AppState` 传递（axum state）是已有的标准模式，与 CORS 和 gRPC auth interceptor 保持一致。无需额外引入全局变量。

## Risks / Trade-offs

**[无 refresh token] → 用户需在 token 过期后重新登录**
首版不实现 refresh token 机制，简化实现。token 有效期默认 24 小时，对于管理面板场景可接受。未来可扩展。

**[HS256 对称密钥] → secret 泄露即可伪造任意 token**
在单服务场景下风险可控。secret 存储在服务器配置文件中，与数据库密码等其他敏感配置同级。建议配合文件权限管理。

**[自动生成 secret] → 重启后 token 失效**
开发便利性与生产可靠性的权衡。通过文档和日志提示引导用户配置固定 secret。

**[破坏性变更] → 现有 API 调用将被拒绝**
无法避免的影响。需在 CHANGELOG 和 README 中明确说明升级步骤：配置 `[auth]` 段 → 启动服务 → 登录获取 token → 在请求中携带 token。

**[单一管理员角色] → 无法细粒度控制权限**
当前用户量小，RBAC 过度设计。表结构预留扩展空间（未来可加 `role` 字段），但首版不实现。

## Migration Plan

1. **新增依赖**: workspace `Cargo.toml` 添加 `jsonwebtoken`
2. **存储层**: `CertStore` 初始化时创建 `users` 表（`CREATE TABLE IF NOT EXISTS`，无破坏性迁移）
3. **启动逻辑**: `main.rs` 中在 `AppState` 创建前执行默认帐号初始化
4. **路由重组**: 将公开路由和受保护路由分离，受保护路由组应用 JWT 中间件 layer
5. **OpenAPI**: 添加 Bearer auth security scheme
6. **部署**: 用户需在 `server.toml` 中添加 `[auth]` 段（可使用全部默认值快速启动）

**回滚策略**: 删除 `[auth]` 配置段并回退到旧版本二进制即可。`users` 表的存在不会影响旧版本运行（SQLite 忽略未使用的表）。

## Open Questions

无 — 需求已明确，技术方案确定。
