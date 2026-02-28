pub use sea_orm_migration::prelude::*;

mod m001_initial_schema;
mod m002_cloud_instances_gpu_integer;
mod m003_cloud_instances_datetime_rfc3339;
mod m004_cloud_instances_auto_renew_flag_bool;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m001_initial_schema::Migration),
            Box::new(m002_cloud_instances_gpu_integer::Migration),
            Box::new(m003_cloud_instances_datetime_rfc3339::Migration),
            Box::new(m004_cloud_instances_auto_renew_flag_bool::Migration),
        ]
    }
}
