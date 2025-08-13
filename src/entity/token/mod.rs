pub mod access;
pub mod auth;
pub mod refresh;

#[macro_export]
macro_rules! impl_verify {
    ($column:ident) => {
        impl Entity {
            pub async fn verify(
                token: &str,
                db: &sea_orm::DatabaseConnection,
            ) -> Result<Option<Model>, sea_orm::DbErr> {
                Self::find()
                    .filter(Column::$column.eq(token))
                    .filter(Column::ExpiresAt.gt(chrono::Utc::now()))
                    .one(db)
                    .await
            }
        }
    };
}
