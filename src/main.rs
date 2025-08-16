use anyhow::Result;
use axum::{
    Router, middleware as axum_mw,
    routing::{get, patch, post},
};
use std::net::SocketAddr;
use tower::ServiceBuilder;

mod db;
mod entity;
mod handler;
mod middleware;
mod templates;
mod util;
mod clients;
use entity::*;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let db = db::init_db().await?;

    let app = Router::new()
        .route("/", get(|| async { "hello from auth" }))
        .merge(
            Router::new()
                .route("/token", post(handler::token::post))
                .route("/revoke", post(handler::revoke::post))
                .layer(axum_mw::from_fn_with_state(
                    db.clone(),
                    middleware::client::client_auth_middleware,
                )),
        )
        .merge(
            Router::new()
                .route("/userinfo", get(handler::userinfo::get))
                .route("/update/user", patch(handler::update::user::patch))
                .layer(axum_mw::from_fn_with_state(
                    db.clone(),
                    middleware::user::user_auth_middleware,
                )),
        )
        .route("/authorize", get(handler::auth::get).post(handler::auth::post))
        .route("/register", get(handler::register::get).post(handler::register::post))
        .route("/success", get(handler::success::get))
        .route("/sdk", get(handler::sdk::get))
        .route("/geolocate", get(handler::geoloc::get))
        .with_state(db)
        .layer(axum_mw::from_fn(middleware::log::log_request))
        .layer(ServiceBuilder::new().into_inner());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
