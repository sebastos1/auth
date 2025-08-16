use anyhow::Result;
use sea_orm::*;

pub async fn create_clients(db: &DatabaseConnection) -> Result<()> {
    let clients = vec![
        // testing client
        (
            "test-client",
            "test-secret",
            "Local Test Client",
            vec!["http://localhost:3001/auth/callback"],
            vec!["openid", "profile", "email"],
        ),
        (
            "sjallabong-main",
            "sjallabong-secret-main-2024",
            "Sjallabong",
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
        println!("Created client: {} / {}", client_id, client_secret);
    }

    Ok(())
}
