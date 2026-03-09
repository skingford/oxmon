use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m011_metrics_alert_events"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN_SQL)
            .await?;
        Ok(())
    }
}

const UP_SQL: &str = "
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    labels TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_agent_metric_time
    ON metrics(agent_id, metric_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_time
    ON metrics(timestamp);

CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    value REAL NOT NULL,
    threshold REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    predicted_breach INTEGER,
    labels TEXT NOT NULL DEFAULT '{}',
    first_triggered_at INTEGER,
    status TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_events_time ON alert_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_events_severity ON alert_events(severity);
CREATE INDEX IF NOT EXISTS idx_alert_events_agent ON alert_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_status ON alert_events(status);
";

const DOWN_SQL: &str = "
DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS metrics;
";
