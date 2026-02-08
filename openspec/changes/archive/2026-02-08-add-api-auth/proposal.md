## Why

当前 oxmon-server 的 25 个 REST API 接口全部公开暴露，无任何鉴权保护。任何能访问服务端口的人都可以直接查看/修改 Agent 白名单、证书监控配置、告警数据等敏感信息。需要新增 JWT 鉴权机制，通过帐号登录获取 token 后才能访问受保护接口。

## What Changes

- 新增用户帐号表（`users`），支持帐号密码管理，字段统一 `id`/`created_at`/`updated_at` 规范
- 新增 `POST /api/v1/auth/login` 登录接口，验证帐号密码后返回 JWT access token
- 新增 JWT 中间件层，对除健康检查和登录外的所有 REST API 接口强制鉴权
- 新增服务启动时自动创建默认管理员帐号（可通过配置文件指定用户名/密码）
- **BREAKING**: 现有所有 REST API 接口（除 `GET /v1/health`）将要求在请求头中携带 `Authorization: Bearer <jwt_token>`
- 新增 `jsonwebtoken` 依赖用于 JWT 签发/验证
- 服务配置文件新增 `auth` 段，包含 JWT secret、token 有效期、默认管理员帐号等

## Capabilities

### New Capabilities
- `api-auth`: REST API 接口 JWT 鉴权，包含用户帐号管理、登录接口、JWT 中间件、权限校验

### Modified Capabilities
- `dashboard-api`: 所有 dashboard API 路由需接入 JWT 鉴权中间件，未携带有效 token 的请求返回 401

## Impact

- **代码**: `oxmon-server`（新增 auth 模块、中间件、登录路由）、`oxmon-storage`（新增 users 表 CRUD）、`oxmon-common`（新增 User/LoginRequest/LoginResponse 类型）
- **API**: 所有 REST 接口（除 health/login）新增 401 响应，请求需携带 Authorization header
- **配置**: `server.toml` 新增 `[auth]` 段
- **依赖**: 新增 `jsonwebtoken` crate
- **OpenAPI**: Swagger 文档新增 Bearer auth security scheme
- **向后兼容**: 破坏性变更 — 现有无 token 的 API 调用将被拒绝
