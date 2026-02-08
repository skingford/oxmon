## 1. 依赖与配置

- [x] 1.1 在 workspace `Cargo.toml` 添加 `jsonwebtoken` 依赖，在 `oxmon-server/Cargo.toml` 引入
- [x] 1.2 在 `oxmon-server/src/config.rs` 新增 `AuthConfig` 结构体（`jwt_secret`、`token_expire_secs`、`default_username`、`default_password`），集成到 `ServerConfig`，所有字段提供默认值
- [x] 1.3 在 `config/server.example.toml` 添加 `[auth]` 段示例配置

## 2. 存储层

- [x] 2.1 在 `oxmon-storage/src/cert_store.rs` 的 `CertStore::new()` 中添加 `users` 表 `CREATE TABLE IF NOT EXISTS` 语句（id/username/password_hash/created_at/updated_at）
- [x] 2.2 在 `CertStore` 中实现 `get_user_by_username(&self, username: &str) -> Result<Option<User>>` 方法
- [x] 2.3 在 `CertStore` 中实现 `create_user(&self, username: &str, password_hash: &str) -> Result<String>` 方法（返回生成的 Snowflake ID）
- [x] 2.4 在 `CertStore` 中实现 `count_users(&self) -> Result<i64>` 方法（用于启动时判断是否需要创建默认帐号）

## 3. 类型定义

- [x] 3.1 在 `oxmon-common/src/types.rs` 新增 `User` 结构体（id、username、created_at、updated_at），派生 Serialize/Deserialize/ToSchema
- [x] 3.2 在 `oxmon-common/src/types.rs` 新增 `LoginRequest`（username、password）和 `LoginResponse`（token、expires_in）结构体，派生 Serialize/Deserialize/ToSchema

## 4. JWT 签发与验证

- [x] 4.1 在 `oxmon-server/src/` 新建 `auth.rs` 模块，定义 `Claims` 结构体（sub、username、iat、exp）
- [x] 4.2 实现 `create_token(secret: &str, user_id: &str, username: &str, expire_secs: u64) -> Result<String>` 函数
- [x] 4.3 实现 `verify_token(secret: &str, token: &str) -> Result<Claims>` 函数

## 5. 登录接口

- [x] 5.1 在 `oxmon-server/src/auth.rs` 或新建 `api/auth.rs` 中实现 `POST /api/v1/auth/login` handler，验证用户名密码后调用 `create_token` 返回 JWT
- [x] 5.2 为 login handler 添加 utoipa `#[utoipa::path]` 注解，生成 OpenAPI 文档

## 6. JWT 中间件

- [x] 6.1 实现 axum middleware 函数 `jwt_auth_middleware`，从 `Authorization: Bearer <token>` 提取并验证 JWT，失败时返回 401 JSON 响应
- [x] 6.2 中间件验证成功后将 `Claims` 写入 request extensions，供下游 handler 可选使用

## 7. 路由重组与 AppState 扩展

- [x] 7.1 在 `AppState` 中新增 `jwt_secret: Arc<String>` 和 `token_expire_secs: u64` 字段
- [x] 7.2 重构 `main.rs` 中的路由组装：将 health、login、openapi/docs 设为公开路由，其余路由组应用 JWT middleware layer
- [x] 7.3 在 `main.rs` 启动流程中添加默认管理员帐号初始化逻辑（检查 users 表是否为空，为空则创建）
- [x] 7.4 在 `main.rs` 中处理 `jwt_secret` 未配置时的自动生成逻辑，并输出 warning 日志

## 8. OpenAPI 文档

- [x] 8.1 在 OpenAPI spec 中添加 Bearer token security scheme（`SecurityAddon` modifier 或 `#[openapi(security(...))]`）
- [x] 8.2 为所有受保护的 endpoint 添加 security 注解，标记需要 Bearer auth
- [x] 8.3 将 login 路由合并到 OpenAPI spec 中

## 9. 验证

- [x] 9.1 `cargo build --release` 编译通过
- [x] 9.2 `cargo test --workspace` 全部测试通过
- [x] 9.3 `cargo clippy --workspace -- -D warnings` 无警告
