use std::time::Duration;

use crate::IS_PRODUCTION;
use anyhow::Result;
use sea_orm::*;

pub async fn init_db() -> Result<DatabaseConnection> {
    let database_url = if *IS_PRODUCTION {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in prod")
    } else {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:auth_dev.db?mode=rwc".to_string())
    };

    let mut opt = ConnectOptions::new(database_url);

    if *IS_PRODUCTION {
        opt.max_connections(20)
            .min_connections(5)
            .connect_timeout(Duration::from_secs(10))
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(3600))
            .sqlx_logging_level(tracing::log::LevelFilter::Info);
    }

    let db = Database::connect(opt).await?;

    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    let stmt = schema.create_table_from_entity(crate::user::Entity);
    let sql = backend
        .build(&stmt)
        .to_string()
        .replace("CREATE TABLE \"users\"", "CREATE TABLE IF NOT EXISTS \"users\"");
    db.execute_unprepared(&sql).await?;

    let stmt = schema.create_table_from_entity(crate::client::Entity);
    let sql = backend
        .build(&stmt)
        .to_string()
        .replace("CREATE TABLE \"clients\"", "CREATE TABLE IF NOT EXISTS \"clients\"");
    db.execute_unprepared(&sql).await?;

    let stmt = schema.create_table_from_entity(crate::token::auth::Entity);
    let sql = backend.build(&stmt).to_string().replace(
        "CREATE TABLE \"auth_codes\"",
        "CREATE TABLE IF NOT EXISTS \"auth_codes\"",
    );
    db.execute_unprepared(&sql).await?;

    let stmt = schema.create_table_from_entity(crate::token::access::Entity);
    let sql = backend.build(&stmt).to_string().replace(
        "CREATE TABLE \"access_tokens\"",
        "CREATE TABLE IF NOT EXISTS \"access_tokens\"",
    );
    db.execute_unprepared(&sql).await?;

    let stmt = schema.create_table_from_entity(crate::token::refresh::Entity);
    let sql = backend.build(&stmt).to_string().replace(
        "CREATE TABLE \"refresh_tokens\"",
        "CREATE TABLE IF NOT EXISTS \"refresh_tokens\"",
    );
    db.execute_unprepared(&sql).await?;

    crate::clients::create_clients(&db).await?;

    Ok(db)
}
