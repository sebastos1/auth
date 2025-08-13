use anyhow::Result;
use sea_orm::*;

pub async fn init_db() -> Result<DatabaseConnection> {
    let db = Database::connect("sqlite:auth.db?mode=rwc").await?;

    let backend = db.get_database_backend();

    let schema = Schema::new(backend);
    let stmt = schema.create_table_from_entity(crate::user::Entity);
    let sql = backend.build(&stmt).to_string().replace(
        "CREATE TABLE \"users\"",
        "CREATE TABLE IF NOT EXISTS \"users\"",
    );
    db.execute_unprepared(&sql).await?;

    let stmt = schema.create_table_from_entity(crate::client::Entity);
    let sql = backend.build(&stmt).to_string().replace(
        "CREATE TABLE \"oauth_clients\"",
        "CREATE TABLE IF NOT EXISTS \"oauth_clients\"",
    );
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

    create_clients(&db).await?;

    Ok(db)
}

pub async fn create_clients(db: &DatabaseConnection) -> Result<()> {
    let clients = vec![
        // testing client
        (
            "test-client",
            "test-secret",
            "Local Test Client",
            vec![
                "http://localhost:3000/auth/callback",
                "http://localhost:3001/auth/callback",
            ],
            vec!["openid", "profile", "email"],
        ),
        (
            "sjallabong-main",
            "sjallabong-secret-main-2024",
            "Sjallabong Main Site",
            vec!["https://sjallabong.eu/auth/callback"],
            vec!["openid", "profile", "email"],
        ),
        (
            "sjallabong-pool",
            "sjallabong-secret-pool-2024",
            "Sjallabong Pool",
            vec!["https://pool.sjallabong.eu/auth/callback"],
            vec!["openid", "profile"],
        ),
    ];

    for (client_id, client_secret, name, redirect_uris, scopes) in clients {
        let existing = crate::client::Entity::find_by_id(client_id).one(db).await?;
        if existing.is_some() {
            continue;
        }

        let client = crate::client::ActiveModel {
            client_id: Set(client_id.to_string()),
            client_secret: Set(client_secret.to_string()),
            name: Set(name.to_string()),
            redirect_uris: Set(serde_json::to_string(&redirect_uris)?),
            allowed_scopes: Set(serde_json::to_string(&scopes)?),
            ..Default::default()
        };

        client.insert(db).await?;
        println!("Created OAuth2 client: {} / {}", client_id, client_secret);
    }

    Ok(())
}
