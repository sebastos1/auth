use chrono::{DateTime, Utc};
use sea_orm::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    // user editable
    #[sea_orm(unique)]
    pub email: String,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub country: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,

    // admin editable
    pub is_moderator: bool,
    pub is_admin: bool,

    pub is_active: bool,
    pub is_member: bool,
    pub is_verified: bool,
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

            // defaults
            is_moderator: Set(false),
            is_admin: Set(false),
            is_active: Set(true),
            is_member: Set(false),
            is_verified: Set(false),

            ..ActiveModelTrait::default()
        }
    }
}

impl Entity {
    pub async fn update_country(user_id: &str, country: &str, db: &DatabaseConnection) -> Result<(), DbErr> {
        let mut user: ActiveModel = Self::find_by_id(user_id).one(db).await?.unwrap().into();
        user.country = Set(Some(country.to_string()));
        user.update(db).await?;
        Ok(())
    }
}
