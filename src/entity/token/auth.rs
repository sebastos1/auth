use chrono::{DateTime, Utc};
use sea_orm::*;
use serde::{Deserialize, Serialize};

const EXPIRATION_MIN: i64 = 10;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "auth_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,

    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            created_at: Set(Utc::now()),
            expires_at: Set(Utc::now() + chrono::Duration::minutes(EXPIRATION_MIN)),
            ..ActiveModelTrait::default()
        }
    }
}

crate::impl_verify!(Code);
