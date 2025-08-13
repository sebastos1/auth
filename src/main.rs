use axum::{routing::{get, post}, Router};
use tower::ServiceBuilder;
use std::net::SocketAddr;
use anyhow::Result;
use tower_http::services::ServeDir;

mod db;
mod entity;
mod handler;
mod templates;
mod errors;
mod util;
use entity::*;

#[tokio::main]
async fn main() -> Result<()> {
    let db = db::init_db().await?;
    let app = Router::new()
        .route("/", get(|| async { "auth" }))
        .route("/authorize", get(handler::auth::get).post(handler::auth::post))
        .route("/token", post(handler::token::post))
        .route("/userinfo", get(handler::userinfo::get))
        .route("/revoke", post(handler::revoke::post))
        .route("/register", get(handler::register::get).post(handler::register::post))
        // .route("/api/register", post(handler::register::register_json))
        .route("/success", get(handler::success::get))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(db)
        .layer(ServiceBuilder::new().into_inner());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    
    Ok(())
}