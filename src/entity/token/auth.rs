use chrono::{DateTime, Utc};
use jsonwebtoken::EncodingKey;
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

impl Entity {
    pub async fn exchange_for_tokens(
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        db: &DatabaseConnection,
        encoding_key: &EncodingKey,
    ) -> Result<(String, String, String, crate::user::Model), DbErr> {
        // (access_token, refresh_token, scopes, user_id)
        let txn = db.begin().await?;

        // validation
        let auth_code = Self::verify(code, &txn)
            .await?
            .ok_or(DbErr::RecordNotFound(String::new()))?;

        if auth_code.client_id != client_id || auth_code.redirect_uri != redirect_uri {
            return Err(DbErr::RecordNotFound(String::new()));
        }

        if !crate::util::verify_pkce(code_verifier, &auth_code.code_challenge) {
            return Err(DbErr::RecordNotFound(String::new()));
        }

        let user = crate::user::Entity::find_by_id(&auth_code.user_id)
            .one(&txn)
            .await?
            .ok_or(DbErr::RecordNotFound("User not found".to_string()))?;

        let access_token =
            crate::token::access::Entity::create(client_id, &user, &auth_code.scopes, &txn, encoding_key).await?;

        let refresh_token = crate::token::refresh::Entity::create(
            &access_token,
            client_id,
            &auth_code.user_id,
            &auth_code.scopes,
            &txn,
        )
        .await?;

        // delete auth code
        Self::delete_by_id(code).exec(&txn).await?;

        let user = crate::user::Entity::find_by_id(auth_code.user_id)
            .one(&txn)
            .await?
            .ok_or(DbErr::RecordNotFound(String::new()))?;

        txn.commit().await?;
        Ok((access_token, refresh_token, auth_code.scopes, user))
    }
}
