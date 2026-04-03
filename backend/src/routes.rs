use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

use crate::{
    handlers::{auth, cert_master, favorites, own_certs, users},
    AppState,
};

pub fn build_router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/signup", post(auth::signup))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/me", get(auth::me));

    let cert_master_routes =
        Router::new().route("/cert-master", get(cert_master::search_cert_master));

    let my_certs_routes = Router::new()
        .route("/", get(own_certs::list_own_certs))
        .route("/", post(own_certs::create_own_cert))
        .route("/:id", put(own_certs::update_own_cert))
        .route("/:id", delete(own_certs::delete_own_cert))
        .route("/:id/hours", patch(own_certs::update_hours))
        .route("/:id/abandon", post(own_certs::abandon_cert))
        .route("/:id/restore", post(own_certs::restore_cert));

    let users_routes = Router::new().route("/users", get(users::list_users));

    let favorites_routes = Router::new()
        .route("/favorites", get(favorites::list_favorites))
        .route("/favorites/:id", post(favorites::add_favorite))
        .route("/favorites/:id", delete(favorites::remove_favorite));

    let api_routes = Router::new()
        .nest("/auth", auth_routes)
        .merge(cert_master_routes)
        .nest("/my/certs", my_certs_routes)
        .merge(users_routes)
        .merge(favorites_routes);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("dist").append_index_html_on_directories(true))
        .layer(cors)
        .with_state(state)
}
