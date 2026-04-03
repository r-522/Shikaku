use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;

use crate::{errors::AppError, middleware::auth::AuthUser, AppState};

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

pub async fn search_cert_master(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    Query(params): Query<SearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    let query = params.q.unwrap_or_default();
    let pattern = format!("%{}%", query);

    let certs = sqlx::query(
        "SELECT cerid, cernm, cerct, certm FROM TBL_CERMAS WHERE cernm ILIKE $1 ORDER BY cernm ASC LIMIT 20",
    )
    .bind(pattern)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result: Vec<serde_json::Value> = certs
        .into_iter()
        .map(|c| {
            json!({
                "cerid": c.try_get::<uuid::Uuid, _>("cerid").ok(),
                "cernm": c.try_get::<String, _>("cernm").ok(),
                "cerct": c.try_get::<Option<String>, _>("cerct").ok().flatten(),
                "certm": c.try_get::<chrono::DateTime<chrono::Utc>, _>("certm").ok(),
            })
        })
        .collect();

    Ok(Json(json!({"data": result, "error": null})))
}
