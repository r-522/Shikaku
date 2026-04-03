mod config;
mod db;
mod errors;
mod handlers;
mod middleware;
mod models;
mod routes;

use std::sync::Arc;

use sqlx::PgPool;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
}

#[tokio::main]
async fn main() {
    // Load .env file if present
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shikaku_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load config from environment
    let config = Config::from_env();
    let port = config.port;

    // Connect to database
    let db = db::create_pool(&config.database_url).await;
    tracing::info!("Connected to database");

    let state = AppState {
        db,
        config: Arc::new(config),
    };

    // Build the router
    let app = routes::build_router(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
