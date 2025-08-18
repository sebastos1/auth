pub mod access;
pub mod auth;
pub mod refresh;

#[macro_export]
macro_rules! impl_verify {
    ($column:ident) => {
        impl Entity {
            pub async fn verify<C>(
                token: &str,
                db: &C,
            ) -> Result<Option<Model>, sea_orm::DbErr> 
            where
                C: sea_orm::ConnectionTrait,
            {
                Self::find()
                    .filter(Column::$column.eq(token))
                    .filter(Column::ExpiresAt.gt(chrono::Utc::now()))
                    .one(db)
                    .await
            }
        }
    };
}