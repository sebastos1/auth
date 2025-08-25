use chrono::{DateTime, Utc};
use sea_orm::*;
use serde::{Deserialize, Serialize};

const EXPIRATION_DAYS: i64 = 30;

// TODO: ROTATION, BLACKLISTING

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

crate::impl_verify!(Token);

impl Entity {
    pub async fn create(
        access_token: &str,
        client_id: &str,
        user_id: &str,
        scopes: &str,
        db: &impl ConnectionTrait,
    ) -> Result<String, DbErr> {
        let refresh_token = crate::util::generate_random_string(64);

        let model = ActiveModel {
            token: Set(refresh_token.clone()),
            access_token: Set(access_token.to_string()),
            client_id: Set(client_id.to_string()),
            user_id: Set(user_id.to_string()),
            scopes: Set(scopes.to_string()),
            ..Default::default()
        };
        model.insert(db).await?;
        Ok(refresh_token)
    }

    pub async fn refresh_tokens(
        refresh_token: &str,
        client_id: &str,
        db: &DatabaseConnection,
    ) -> Result<(String, String, String, crate::user::Model), DbErr> {
        let txn = db.begin().await?;

        let refresh_record = Self::verify(refresh_token, &txn)
            .await?
            .ok_or(DbErr::RecordNotFound(String::new()))?;

        if refresh_record.client_id != client_id {
            return Err(DbErr::RecordNotFound(String::new()));
        }

        // delete old
        crate::token::access::Entity::delete_by_id(&refresh_record.access_token)
            .exec(&txn)
            .await?;
        Self::delete_by_id(refresh_token).exec(&txn).await?;

        // new
        let access_token =
            crate::token::access::Entity::create(client_id, &refresh_record.user_id, &refresh_record.scopes, &txn)
                .await?;
        let refresh_token = Self::create(
            &access_token,
            client_id,
            &refresh_record.user_id,
            &refresh_record.scopes,
            &txn,
        )
        .await?;

        let user = crate::user::Entity::find_by_id(refresh_record.user_id).one(&txn).await?.ok_or(DbErr::RecordNotFound(String::new()))?;

        txn.commit().await?;
        Ok((access_token, refresh_token, refresh_record.scopes, user))
    }

    pub async fn revoke(token: &str, client_id: &str, db: &DatabaseConnection) -> Result<bool, DbErr> {
        let Some(refresh_token) = Self::find_by_id(token).one(db).await? else {
            return Ok(false);
        };

        if refresh_token.client_id != client_id {
            return Ok(false);
        }

        let txn = db.begin().await?;

        // delete both access and refresh tokens
        Self::delete_by_id(token).exec(&txn).await?;
        crate::token::access::Entity::delete_by_id(&refresh_token.access_token)
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok(true)
    }
}
