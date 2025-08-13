use sea_orm::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_clients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: String,
    pub allowed_scopes: String,
    pub is_trusted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            created_at: Set(chrono::Utc::now()),
            is_trusted: Set(false),
            ..ActiveModelTrait::default()
        }
    }
}

impl Model {
    pub fn _get_redirect_uris(&self) -> Result<Vec<String>, serde_json::Error> {
        serde_json::from_str(&self.redirect_uris)
    }
    
    pub fn get_allowed_scopes(&self) -> Result<Vec<String>, serde_json::Error> {
        serde_json::from_str(&self.allowed_scopes)
    }
}