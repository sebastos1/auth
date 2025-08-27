use anyhow::Result;
use sea_orm::*;

// remove localhosts in prod. Or actually just make /update endpoints
pub async fn create_clients(db: &DatabaseConnection) -> Result<()> {
    let clients = vec![
        (
            "sjallabong-main",
            "Sjallabong",
            vec!["https://sjallabong.eu/auth/callback"],
            vec!["openid", "profile", "email"],
            vec!["https://sjallabong.eu", "http://localhost:5173"],
        ),
        (
            "sjallabong-pool",
            "Sjallabong Pool",
            vec!["https://sjallabong.eu/auth/callback"],
            vec!["openid", "profile"],
            vec!["https://pool.sjallabong.eu", "http://localhost:8080"],
        ),
        (
            "chattabong",
            "Chattabong",
            vec!["https://sjallabong.eu/auth/callback", "http://localhost:5173/auth/callback"],
            vec!["openid", "profile", "roles"],
            vec!["https://sjallabong.eu", "http://localhost:5173"],
        ),
    ];

    for (client_id, name, redirect_uris, scopes, origins) in clients {
        let existing = crate::client::Entity::find_by_id(client_id).one(db).await?;
        if existing.is_some() {
            continue;
        }

        let client = crate::client::ActiveModel {
            client_id: Set(client_id.to_string()),
            name: Set(name.to_string()),
            redirect_uris: Set(serde_json::to_string(&redirect_uris)?),
            allowed_scopes: Set(serde_json::to_string(&scopes)?),
            authorized_origins: Set(serde_json::to_string(&origins)?),
            ..Default::default()
        };

        client.insert(db).await?;
        tracing::info!("Created client: {client_id}");
    }

    Ok(())
}
