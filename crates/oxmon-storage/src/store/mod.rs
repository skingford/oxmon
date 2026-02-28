use anyhow::Result;
use migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use std::path::Path;

use crate::auth::TokenEncryptor;

pub mod agent;
pub mod ai;
pub mod alert;
pub mod cert;
pub mod cloud;
pub mod config;
pub mod dictionary;
pub mod notification;
pub mod user;

// ---- 公开 Row 类型（从各子模块重新导出）----
pub use alert::{AlertRuleFilter, AlertRuleRow, AlertRuleUpdate};
pub use cloud::{
    CloudAccountRow, CloudAccountSummary, CloudCollectionStateRow, CloudInstanceRow,
    CloudInstanceStatusSummary,
};
pub use config::{SystemConfigFilter, SystemConfigRow, SystemConfigUpdate};
pub use ai::AIAccountRow;
pub use notification::{
    ActiveAlertFilter, NotificationChannelFilter, NotificationChannelRow,
    NotificationChannelUpdate, NotificationLogFilter, NotificationLogRow,
    NotificationRecipientRow, SilenceWindowFilter, SilenceWindowRow,
};
pub use agent::{AgentListFilter, AgentWhitelistFilter};
pub use cert::{CertDomainSummary, CertHealthSummary, CertStatusFilter, CertStatusSummary};
pub use dictionary::DictTypeFilter;

/// 管理数据库（oxmon.db）的统一访问层。
///
/// 所有方法均为 `async fn`，底层使用 SeaORM + SQLite。
/// 时序分片存储（每日 .db 文件）仍由 `SqliteStorageEngine` 管理。
pub struct CertStore {
    pub(crate) db: DatabaseConnection,
    pub(crate) token_encryptor: TokenEncryptor,
}

impl CertStore {
    /// 连接并初始化管理数据库。
    ///
    /// - `db_url`：完整的数据库连接 URL，由调用方（服务器配置）提供。
    ///   SQLite 示例：`sqlite:///data/oxmon.db?mode=rwc`
    ///   PostgreSQL 示例：`postgres://user:pass@localhost:5432/oxmon`
    /// - `data_dir`：本地数据目录，用于存放 Token 加密密钥文件，与数据库类型无关。
    ///
    /// 自动运行 `sea-orm-migration` 迁移，确保 Schema 最新。
    pub async fn new(db_url: &str, data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db = Database::connect(db_url).await?;

        // WAL 模式仅对 SQLite 有效
        if db_url.starts_with("sqlite://") {
            db.execute_unprepared("PRAGMA journal_mode=WAL;").await?;
        }

        // 运行所有待执行迁移
        Migrator::up(&db, None).await?;

        let token_encryptor = TokenEncryptor::load_or_create(data_dir)?;
        tracing::info!(db_url = %db_url, "Initialized cert store (SeaORM)");

        Ok(Self { db, token_encryptor })
    }

    /// 返回底层数据库连接引用（供子模块使用）。
    pub(crate) fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
