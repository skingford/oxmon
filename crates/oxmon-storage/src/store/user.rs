use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::User;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

use crate::entities::user::{self, Column, Entity};
use crate::store::CertStore;

fn to_user(m: user::Model) -> User {
    User {
        id: m.id,
        username: m.username,
        password_hash: m.password_hash,
        token_version: m.token_version as i64,
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

    pub async fn create_user(&self, username: &str, password_hash: &str) -> Result<String> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let am = user::ActiveModel {
            id: Set(id.clone()),
            username: Set(username.to_owned()),
            password_hash: Set(password_hash.to_owned()),
            token_version: Set(0),
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
        let now = Utc::now().fixed_offset();
        let am = user::ActiveModel {
            id: Set(user_id.to_owned()),
            password_hash: Set(password_hash.to_owned()),
            token_version: sea_orm::ActiveValue::NotSet,
            updated_at: Set(now),
            ..Default::default()
        };
        // increment token_version
        let model = Entity::find_by_id(user_id).one(self.db()).await?;
        if let Some(m) = model {
            let mut active: user::ActiveModel = m.into();
            active.password_hash = Set(password_hash.to_owned());
            active.token_version = Set(active.token_version.unwrap() + 1);
            active.updated_at = Set(now);
            active.update(self.db()).await?;
            Ok(true)
        } else {
            drop(am);
            Ok(false)
        }
    }

    pub async fn count_users(&self) -> Result<i64> {
        let count = Entity::find().count(self.db()).await?;
        Ok(count as i64)
    }
}
