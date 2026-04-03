use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::{errors::AppError, middleware::auth::AuthUser, AppState};

pub async fn list_favorites(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let favs = sqlx::query!(
        "SELECT favtg FROM TBL_FAVORI WHERE favus = $1 ORDER BY favtm DESC",
        auth_user.useid
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let ids: Vec<Uuid> = favs.into_iter().map(|f| f.favtg).collect();

    Ok(Json(json!({"data": ids, "error": null})))
}

pub async fn add_favorite(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(target_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if target_id == auth_user.useid {
        return Err(AppError::BadRequest("Cannot favorite yourself".to_string()));
    }

    // Verify target user exists
    let target = sqlx::query!("SELECT useid FROM TBL_USER WHERE useid = $1", target_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    if target.is_none() {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    let favid = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO TBL_FAVORI (favid, favus, favtg, favtm)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        "#,
        favid,
        auth_user.useid,
        target_id,
        now
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    Ok(Json(json!({"data": null, "error": null})))
}

pub async fn remove_favorite(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(target_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query!(
        "DELETE FROM TBL_FAVORI WHERE favus = $1 AND favtg = $2",
        auth_user.useid,
        target_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    Ok(Json(json!({"data": null, "error": null})))
}
