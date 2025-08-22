use chrono::{DateTime, Utc};
use sea_orm::*;
use serde::{Deserialize, Serialize};

const EXPIRATION_MIN: i64 = 60 * 24;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "access_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token: String,
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
            expires_at: Set(Utc::now() + chrono::Duration::minutes(EXPIRATION_MIN)),
            ..ActiveModelTrait::default()
        }
    }
}

crate::impl_verify!(Token);

impl Entity {
    pub async fn create(
        client_id: &str, 
        user_id: &str,
        scopes: &str,
        db: &impl ConnectionTrait,
    ) -> Result<String, DbErr> {
        let access_token = crate::util::generate_random_string(64);
        let model = ActiveModel {
            token: Set(access_token.clone()),
            client_id: Set(client_id.to_string()),
            user_id: Set(user_id.to_string()),
            scopes: Set(scopes.to_string()),
            ..Default::default()
        };
        model.insert(db).await?;
        Ok(access_token)
    }

    pub async fn revoke(
        token: &str,
        client_id: &str,
        db: &DatabaseConnection,
    ) -> Result<bool, DbErr> {
        let Some(access_token) = Self::find_by_id(token).one(db).await? else {
            return Ok(false);
        };

        if access_token.client_id != client_id {
            return Ok(false);
        }

        let txn = db.begin().await?;

        Self::delete_by_id(token).exec(&txn).await?;

        // remove associated refresh token
        if let Some(refresh) = crate::token::refresh::Entity::find()
            .filter(crate::token::refresh::Column::AccessToken.eq(token))
            .one(&txn).await? {
            crate::token::refresh::Entity::delete_by_id(&refresh.token).exec(&txn).await?;
        }

        txn.commit().await?;
        Ok(true)
    }
}