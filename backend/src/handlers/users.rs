use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;
use sqlx::Row;

use crate::{errors::AppError, middleware::auth::AuthUser, AppState};

pub async fn list_users(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let users = sqlx::query(
        r#"
        SELECT
            u.useid,
            u.usenm,
            COUNT(DISTINCT o.ownid) FILTER (WHERE o.ownfl = false) AS cert_count,
            COUNT(DISTINCT o.ownid) FILTER (WHERE o.ownfl = false AND o.ownst = 'passed') AS passed_count,
            EXISTS(
                SELECT 1 FROM TBL_FAVORI f WHERE f.favus = $1 AND f.favtg = u.useid
            ) AS is_favorite
        FROM TBL_USER u
        LEFT JOIN TBL_OWNCER o ON o.ownus = u.useid
        GROUP BY u.useid, u.usenm
        ORDER BY is_favorite DESC, u.usenm ASC
        "#,
    )
    .bind(auth_user.useid)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            json!({
                "useid": u.try_get::<uuid::Uuid, _>("useid").ok(),
                "usenm": u.try_get::<String, _>("usenm").ok(),
                "cert_count": u.try_get::<Option<i64>, _>("cert_count").ok().flatten().unwrap_or(0),
                "passed_count": u.try_get::<Option<i64>, _>("passed_count").ok().flatten().unwrap_or(0),
                "is_favorite": u.try_get::<Option<bool>, _>("is_favorite").ok().flatten().unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(json!({"data": result, "error": null})))
}
