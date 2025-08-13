use sea_orm::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub email: String,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub is_active: bool,
    pub country: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            id: Set(uuid::Uuid::new_v4().to_string()),
            created_at: Set(chrono::Utc::now()),
            updated_at: Set(chrono::Utc::now()),
            last_login_at: Set(None),
            ..ActiveModelTrait::default()
        }
    }
}