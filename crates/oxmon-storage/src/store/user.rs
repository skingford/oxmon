use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::User;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};

use crate::entities::login_throttle::{self as login_throttle, Entity as LoginThrottleEntity};
use crate::entities::user::{self, Column, Entity};
use crate::store::CertStore;

#[derive(Debug, Clone)]
pub struct LoginThrottleRow {
    pub id: String,
    pub username: String,
    pub ip_address: String,
    pub failure_count: i32,
    pub last_failed_at: String,
    pub locked_until: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct LoginThrottleFilter {
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub locked_only: bool,
}

fn normalize_login_ip(ip_address: Option<&str>) -> String {
    ip_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn login_throttle_key(username: &str, ip_address: Option<&str>) -> String {
    format!(
        "{}|{}",
        username.trim().to_ascii_lowercase(),
        normalize_login_ip(ip_address)
    )
}

fn login_throttle_model_to_row(m: login_throttle::Model) -> LoginThrottleRow {
    LoginThrottleRow {
        id: m.id,
        username: m.username,
        ip_address: m.ip_address,
        failure_count: m.failure_count,
        last_failed_at: m.last_failed_at.with_timezone(&Utc).to_rfc3339(),
        locked_until: m
            .locked_until
            .map(|value| value.with_timezone(&Utc).to_rfc3339()),
        updated_at: m.updated_at.with_timezone(&Utc).to_rfc3339(),
    }
}

fn to_user(m: user::Model) -> User {
    User {
        id: m.id,
        username: m.username,
        password_hash: m.password_hash,
        token_version: m.token_version as i64,
        status: m.status,
        avatar: m.avatar,
        phone: m.phone,
        email: m.email,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let model = Entity::find()
            .filter(Column::Username.eq(username))
            .one(self.db())
            .await?;
        Ok(model.map(to_user))
    }

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        status: Option<&str>,
        avatar: Option<&str>,
        phone: Option<&str>,
        email: Option<&str>,
    ) -> Result<String> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let am = user::ActiveModel {
            id: Set(id.clone()),
            username: Set(username.to_owned()),
            password_hash: Set(password_hash.to_owned()),
            token_version: Set(0),
            status: Set(status.unwrap_or("active").to_owned()),
            avatar: Set(avatar.map(|s| s.to_owned())),
            phone: Set(phone.map(|s| s.to_owned())),
            email: Set(email.map(|s| s.to_owned())),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        Ok(id)
    }

    pub async fn update_user_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<bool> {
        let model = Entity::find_by_id(user_id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut active: user::ActiveModel = m.into();
            active.password_hash = Set(password_hash.to_owned());
            active.token_version = Set(active.token_version.unwrap() + 1);
            active.updated_at = Set(now);
            active.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn list_login_throttles(
        &self,
        filter: &LoginThrottleFilter,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<LoginThrottleRow>> {
        let now = Utc::now().fixed_offset();
        let mut query = LoginThrottleEntity::find();

        if let Some(username) = &filter.username {
            query = query
                .filter(login_throttle::Column::Username.eq(username.trim().to_ascii_lowercase()));
        }
        if let Some(ip_address) = &filter.ip_address {
            query = query.filter(login_throttle::Column::IpAddress.eq(ip_address.trim()));
        }
        if filter.locked_only {
            query = query.filter(login_throttle::Column::LockedUntil.gt(now));
        }

        let rows = query
            .order_by(login_throttle::Column::LockedUntil, Order::Desc)
            .order_by(login_throttle::Column::UpdatedAt, Order::Desc)
            .limit(limit)
            .offset(offset)
            .all(self.db())
            .await?
            .into_iter()
            .map(login_throttle_model_to_row)
            .collect();
        Ok(rows)
    }

    pub async fn count_login_throttles(&self, filter: &LoginThrottleFilter) -> Result<u64> {
        let now = Utc::now().fixed_offset();
        let mut query = LoginThrottleEntity::find();

        if let Some(username) = &filter.username {
            query = query
                .filter(login_throttle::Column::Username.eq(username.trim().to_ascii_lowercase()));
        }
        if let Some(ip_address) = &filter.ip_address {
            query = query.filter(login_throttle::Column::IpAddress.eq(ip_address.trim()));
        }
        if filter.locked_only {
            query = query.filter(login_throttle::Column::LockedUntil.gt(now));
        }

        Ok(query.count(self.db()).await?)
    }

    pub async fn get_login_lock_until(
        &self,
        username: &str,
        ip_address: Option<&str>,
        lock_duration_hours: i64,
    ) -> Result<Option<DateTime<Utc>>> {
        let key = login_throttle_key(username, ip_address);
        let model = LoginThrottleEntity::find_by_id(key).one(self.db()).await?;
        let now = Utc::now();
        if let Some(model) = model {
            if let Some(locked_until) = model.locked_until {
                let locked_until_utc = locked_until.with_timezone(&Utc);
                if locked_until_utc > now {
                    return Ok(Some(locked_until_utc));
                }
            }

            if now - model.last_failed_at.with_timezone(&Utc)
                >= Duration::hours(lock_duration_hours)
            {
                LoginThrottleEntity::delete_by_id(model.id)
                    .exec(self.db())
                    .await?;
            }
        }
        Ok(None)
    }

    pub async fn register_login_failure(
        &self,
        username: &str,
        ip_address: Option<&str>,
        failure_threshold: u32,
        lock_duration_hours: i64,
    ) -> Result<Option<DateTime<Utc>>> {
        let key = login_throttle_key(username, ip_address);
        let normalized_ip = normalize_login_ip(ip_address);
        let now = Utc::now();
        let now_fixed = now.fixed_offset();
        let model = LoginThrottleEntity::find_by_id(key.clone())
            .one(self.db())
            .await?;

        if let Some(model) = model {
            let mut active: login_throttle::ActiveModel = model.into();
            let stale = now - active.last_failed_at.clone().unwrap().with_timezone(&Utc)
                >= Duration::hours(lock_duration_hours);
            let current_count = if stale {
                0
            } else {
                active.failure_count.clone().unwrap()
            };
            let next_count = current_count + 1;
            let locked_until = if next_count >= failure_threshold as i32 {
                Some((now + Duration::hours(lock_duration_hours)).fixed_offset())
            } else {
                None
            };
            active.username = Set(username.trim().to_ascii_lowercase());
            active.ip_address = Set(normalized_ip);
            active.failure_count = Set(next_count);
            active.last_failed_at = Set(now_fixed);
            active.locked_until = Set(locked_until);
            active.updated_at = Set(now_fixed);
            let updated = active.update(self.db()).await?;
            Ok(updated.locked_until.map(|value| value.with_timezone(&Utc)))
        } else {
            let locked_until = None;
            let active = login_throttle::ActiveModel {
                id: Set(key),
                username: Set(username.trim().to_ascii_lowercase()),
                ip_address: Set(normalized_ip),
                failure_count: Set(1),
                last_failed_at: Set(now_fixed),
                locked_until: Set(locked_until),
                created_at: Set(now_fixed),
                updated_at: Set(now_fixed),
            };
            active.insert(self.db()).await?;
            Ok(None)
        }
    }

    pub async fn list_expired_login_throttles(
        &self,
        lock_duration_hours: i64,
    ) -> Result<Vec<LoginThrottleRow>> {
        let now = Utc::now().fixed_offset();
        let stale_cutoff = (Utc::now() - Duration::hours(lock_duration_hours)).fixed_offset();
        let rows = LoginThrottleEntity::find()
            .filter(
                Condition::any()
                    .add(login_throttle::Column::LockedUntil.lte(now))
                    .add(
                        Condition::all()
                            .add(login_throttle::Column::LockedUntil.is_null())
                            .add(login_throttle::Column::UpdatedAt.lte(stale_cutoff)),
                    ),
            )
            .all(self.db())
            .await?
            .into_iter()
            .map(login_throttle_model_to_row)
            .collect();
        Ok(rows)
    }

    pub async fn cleanup_expired_login_throttles(&self, lock_duration_hours: i64) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let now = Utc::now().fixed_offset();
        let stale_cutoff = (Utc::now() - Duration::hours(lock_duration_hours)).fixed_offset();
        let sql = format!(
            "DELETE FROM login_throttles WHERE (locked_until IS NOT NULL AND locked_until <= '{}') OR (locked_until IS NULL AND updated_at <= '{}')",
            now.to_rfc3339(),
            stale_cutoff.to_rfc3339()
        );
        let result = self
            .db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn clear_login_failures(
        &self,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let key = login_throttle_key(username, ip_address);
        LoginThrottleEntity::delete_by_id(key)
            .exec(self.db())
            .await?;
        Ok(())
    }

    pub async fn clear_login_failures_by_username(&self, username: &str) -> Result<u64> {
        let normalized = username.trim().to_ascii_lowercase();
        let result = LoginThrottleEntity::delete_many()
            .filter(login_throttle::Column::Username.eq(normalized))
            .exec(self.db())
            .await?;
        Ok(result.rows_affected)
    }

    pub async fn bump_user_token_version(&self, user_id: &str) -> Result<bool> {
        let model = Entity::find_by_id(user_id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut active: user::ActiveModel = m.into();
            active.token_version = Set(active.token_version.unwrap() + 1);
            active.updated_at = Set(now);
            active.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 更新用户基本信息（status / avatar / phone / email），仅更新传入的非 None 字段。
    pub async fn update_user(
        &self,
        user_id: &str,
        status: Option<&str>,
        avatar: Option<&str>,
        phone: Option<&str>,
        email: Option<&str>,
    ) -> Result<bool> {
        let model = Entity::find_by_id(user_id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut active: user::ActiveModel = m.into();
            if let Some(s) = status {
                active.status = Set(s.to_owned());
            }
            if let Some(a) = avatar {
                active.avatar = Set(Some(a.to_owned()));
            }
            if let Some(p) = phone {
                active.phone = Set(Some(p.to_owned()));
            }
            if let Some(e) = email {
                active.email = Set(Some(e.to_owned()));
            }
            active.updated_at = Set(now);
            active.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn count_users(&self) -> Result<i64> {
        let count = Entity::find().count(self.db()).await?;
        Ok(count as i64)
    }

    pub async fn list_users(
        &self,
        username_contains: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<User>> {
        let mut query = Entity::find();
        if let Some(name) = username_contains {
            query = query.filter(Column::Username.contains(name));
        }
        let models = query
            .order_by(Column::CreatedAt, Order::Asc)
            .limit(limit)
            .offset(offset)
            .all(self.db())
            .await?;
        Ok(models.into_iter().map(to_user).collect())
    }

    pub async fn count_users_filtered(&self, username_contains: Option<&str>) -> Result<i64> {
        let mut query = Entity::find();
        if let Some(name) = username_contains {
            query = query.filter(Column::Username.contains(name));
        }
        let count = query.count(self.db()).await?;
        Ok(count as i64)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<User>> {
        let model = Entity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(to_user))
    }

    pub async fn delete_user(&self, id: &str) -> Result<bool> {
        let result = Entity::delete_by_id(id).exec(self.db()).await?;
        Ok(result.rows_affected > 0)
    }
}
