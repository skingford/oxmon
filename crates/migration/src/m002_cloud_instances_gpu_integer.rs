use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m002_cloud_instances_gpu_integer"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

const UP_SQL: &str = r#"
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS cloud_instances__new (
    id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    instance_name TEXT,
    provider TEXT NOT NULL,
    account_config_key TEXT NOT NULL,
    region TEXT NOT NULL,
    public_ip TEXT,
    private_ip TEXT,
    os TEXT,
    status TEXT,
    instance_type TEXT,
    cpu_cores INTEGER,
    memory_gb REAL,
    disk_gb REAL,
    created_time TEXT,
    expired_time TEXT,
    charge_type TEXT,
    vpc_id TEXT,
    subnet_id TEXT,
    security_group_ids TEXT,
    zone TEXT,
    internet_max_bandwidth INTEGER,
    ipv6_addresses TEXT,
    eip_allocation_id TEXT,
    internet_charge_type TEXT,
    image_id TEXT,
    hostname TEXT,
    description TEXT,
    gpu INTEGER,
    io_optimized TEXT,
    latest_operation TEXT,
    latest_operation_state TEXT,
    tags TEXT,
    project_id TEXT,
    resource_group_id TEXT,
    auto_renew_flag INTEGER,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, instance_id)
);

INSERT INTO cloud_instances__new (
    id, instance_id, instance_name, provider, account_config_key, region,
    public_ip, private_ip, os, status, instance_type, cpu_cores, memory_gb, disk_gb,
    created_time, expired_time, charge_type, vpc_id, subnet_id, security_group_ids, zone,
    internet_max_bandwidth, ipv6_addresses, eip_allocation_id, internet_charge_type,
    image_id, hostname, description, gpu, io_optimized, latest_operation, latest_operation_state,
    tags, project_id, resource_group_id, auto_renew_flag, last_seen_at, created_at, updated_at
)
SELECT
    id, instance_id, instance_name, provider, account_config_key, region,
    public_ip, private_ip, os, status, instance_type, cpu_cores, memory_gb, disk_gb,
    created_time, expired_time, charge_type, vpc_id, subnet_id, security_group_ids, zone,
    internet_max_bandwidth, ipv6_addresses, eip_allocation_id, internet_charge_type,
    image_id, hostname, description,
    CASE
        WHEN gpu IS NULL THEN NULL
        WHEN typeof(gpu) = 'integer' THEN gpu
        WHEN typeof(gpu) = 'real' THEN CAST(gpu AS INTEGER)
        WHEN trim(CAST(gpu AS TEXT)) = '' THEN NULL
        WHEN trim(CAST(gpu AS TEXT)) GLOB '-[0-9][0-9]*' THEN CAST(trim(CAST(gpu AS TEXT)) AS INTEGER)
        WHEN trim(CAST(gpu AS TEXT)) GLOB '[0-9][0-9]*' THEN CAST(trim(CAST(gpu AS TEXT)) AS INTEGER)
        ELSE NULL
    END AS gpu,
    io_optimized, latest_operation, latest_operation_state,
    tags, project_id, resource_group_id, auto_renew_flag, last_seen_at, created_at, updated_at
FROM cloud_instances;

DROP TABLE cloud_instances;
ALTER TABLE cloud_instances__new RENAME TO cloud_instances;

CREATE INDEX IF NOT EXISTS idx_cloud_instances_provider ON cloud_instances(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_region ON cloud_instances(region);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_account_key ON cloud_instances(account_config_key);

COMMIT;
PRAGMA foreign_keys=ON;
"#;

