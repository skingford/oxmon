use anyhow::Result;
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::CertStore;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use super::report::generate_report_for_account;

pub struct AIReportScheduler {
    storage: Arc<SqliteStorageEngine>,
    cert_store: Arc<CertStore>,
    notifier: Arc<NotificationManager>,
    tick_interval: Duration,
    #[allow(dead_code)]
    history_days: i32,
}

impl AIReportScheduler {
    pub fn new(
        storage: Arc<SqliteStorageEngine>,
        cert_store: Arc<CertStore>,
        notifier: Arc<NotificationManager>,
        tick_interval: Duration,
        history_days: i32,
    ) -> Self {
        Self {
            storage,
            cert_store,
            notifier,
            tick_interval,
            history_days,
        }
    }

    pub async fn start(self: Arc<Self>) {
        let mut ticker = time::interval(self.tick_interval);

        loop {
            ticker.tick().await;

            if let Err(e) = self.collect_due_accounts().await {
                tracing::error!(error = %e, "AI report scheduler tick failed");
            }
        }
    }

    async fn collect_due_accounts(&self) -> Result<()> {
        // 1. 检查是否启用定时发送
        let schedule_enabled = self
            .cert_store
            .get_runtime_setting_bool("ai_report_schedule_enabled", true)
            .await;

        if !schedule_enabled {
            tracing::debug!("AI report schedule is disabled");
            return Ok(());
        }

        // 2. 加载所有启用的 AI 账号
        let accounts = self
            .cert_store
            .list_ai_accounts(None, Some(true), 1000, 0)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load AI accounts: {}", e))?;

        if accounts.is_empty() {
            return Ok(());
        }

        // 3. 获取配置的发送时间
        let schedule_time = self
            .cert_store
            .get_runtime_setting_string("ai_report_schedule_time", "08:00")
            .await;

        // 4. 检查每个账号是否到期需要生成报告
        for account in accounts {
            let interval_secs = account
                .collection_interval_secs
                .map(|v| v as i64)
                .unwrap_or(86400);

            let should_collect = self
                .should_collect(&account.config_key, interval_secs, &schedule_time)
                .await?;

            if should_collect {
                tracing::info!(
                    account_id = %account.id,
                    config_key = %account.config_key,
                    "AI account is due for report generation"
                );

                if let Err(e) = generate_report_for_account(
                    &account,
                    &self.storage,
                    &self.cert_store,
                    &self.notifier,
                )
                .await
                {
                    tracing::error!(
                        account_id = %account.id,
                        error = %e,
                        "Failed to generate AI report"
                    );
                }
            }
        }

        Ok(())
    }

    async fn should_collect(
        &self,
        config_key: &str,
        interval_secs: i64,
        schedule_time: &str,
    ) -> Result<bool> {
        let last_report = self
            .cert_store
            .get_latest_ai_report_by_account(config_key)
            .await?;

        let now = chrono::Utc::now();

        let Some(last_report) = last_report else {
            return Ok(true);
        };
        let last_report_date = last_report.created_at.date_naive();
        let today = now.date_naive();

        if last_report_date == today {
            return Ok(false);
        }

        let (target_hour, target_minute) = match self.parse_time(schedule_time) {
            Ok((h, m)) => (h, m),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    schedule_time = %schedule_time,
                    "Failed to parse schedule time, using interval mode"
                );
                let elapsed = now.timestamp() - last_report.created_at.timestamp();
                return Ok(elapsed >= interval_secs);
            }
        };

        let current_time = now.time();
        let target_time = chrono::NaiveTime::from_hms_opt(target_hour, target_minute, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid time components"))?;

        Ok(current_time >= target_time)
    }

    fn parse_time(&self, time_str: &str) -> Result<(u32, u32)> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid time format, expected HH:MM");
        }
        let hour: u32 = parts[0]
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse hour"))?;
        let minute: u32 = parts[1]
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse minute"))?;
        if hour >= 24 {
            anyhow::bail!("Hour must be between 0-23");
        }
        if minute >= 60 {
            anyhow::bail!("Minute must be between 0-59");
        }
        Ok((hour, minute))
    }
}
