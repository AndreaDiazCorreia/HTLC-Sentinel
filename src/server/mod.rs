pub mod handlers;
pub mod types;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use crate::api::source::DataSource;
use crate::security::types::SecurityConfig;

use handlers::{AppState, ServerState};

pub fn create_router<S: DataSource + Send + Sync + 'static>(
    client: S,
    config: SecurityConfig,
) -> Router {
    let state: AppState<S> = Arc::new(ServerState { client, config });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/tx/{txid}", get(handlers::get_transaction::<S>))
        .route("/api/block/{height}", get(handlers::get_block::<S>))
        .route("/api/scan", get(handlers::get_scan::<S>))
        .route("/api/lightning", get(handlers::get_lightning::<S>))
        .route("/api/monitor", get(handlers::get_monitor::<S>))
        .layer(cors)
        .with_state(state)
}
