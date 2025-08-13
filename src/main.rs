use anyhow::Result;
use axum::{
    Router,
    routing::{get, patch, post},
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::services::ServeDir;

mod db;
mod entity;
mod errors;
mod handler;
mod templates;
mod util;
use entity::*;

#[tokio::main]
async fn main() -> Result<()> {
    let db = db::init_db().await?;
    let app = Router::new()
        .route("/", get(|| async { "auth" }))
        .route(
            "/authorize",
            get(handler::auth::get).post(handler::auth::post),
        )
        .route("/token", post(handler::token::post))
        .route("/userinfo", get(handler::userinfo::get))
        .route("/revoke", post(handler::revoke::post))
        .route(
            "/register",
            get(handler::register::get).post(handler::register::post),
        )
        .route("/success", get(handler::success::get))
        .route("/update/user", patch(handler::update::user::patch))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(db)
        .layer(ServiceBuilder::new().into_inner());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
