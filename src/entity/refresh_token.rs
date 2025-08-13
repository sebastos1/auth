use sea_orm::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

const EXPIRATION_DAYS: i64 = 30;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token: String,
    pub access_token: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            created_at: Set(Utc::now()),
            expires_at: Set(Utc::now() + chrono::Duration::days(EXPIRATION_DAYS)),
            ..ActiveModelTrait::default()
        }
    }
}