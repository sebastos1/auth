use anyhow::Result;
use axum::{
    Router, middleware as axum_mw,
    routing::{get, patch, post},
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod entity;
mod handler;
mod middleware;
mod templates;
mod util;
mod error;
mod clients;
use entity::{user, client, token};

use std::sync::LazyLock;

static IS_PRODUCTION: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("AUTH_ENV").unwrap_or_else(|_| "development".to_string()) == "production"
});

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "auth=debug,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // todo
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let db = db::init_db().await?;

    let app = Router::new()
        .route("/", get(|| async { "hello from auth" }))
        .route("/token", post(handler::token::post))
        .route("/revoke", post(handler::revoke::post))
        .merge(Router::new()
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
        .layer(ServiceBuilder::new().into_inner())
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
