use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{errors::AppError, middleware::auth::AuthUser, AppState};

#[derive(Debug, Deserialize)]
pub struct CreateOwnCertRequest {
    pub ownnm: String,
    pub ownce: Option<Uuid>,
    pub ownst: String,
    pub owntg: Option<chrono::NaiveDate>,
    pub ownhr: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOwnCertRequest {
    pub ownnm: String,
    pub ownce: Option<Uuid>,
    pub ownst: String,
    pub owntg: Option<chrono::NaiveDate>,
    pub ownhr: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct HoursRequest {
    pub delta: Option<f64>,
    pub value: Option<f64>,
}

fn is_valid_status(s: &str) -> bool {
    matches!(s, "studying" | "passed" | "failed" | "abandoned")
}

pub async fn list_own_certs(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let certs = sqlx::query!(
        r#"
        SELECT ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        FROM TBL_OWNCER
        WHERE ownus = $1 AND ownfl = false
        ORDER BY owntm DESC
        "#,
        auth_user.useid
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result: Vec<serde_json::Value> = certs
        .into_iter()
        .map(|c| {
            json!({
                "ownid": c.ownid,
                "ownus": c.ownus,
                "ownnm": c.ownnm,
                "ownce": c.ownce,
                "ownst": c.ownst,
                "owntg": c.owntg,
                "ownhr": c.ownhr,
                "ownfl": c.ownfl,
                "owntm": c.owntm,
                "ownup": c.ownup,
            })
        })
        .collect();

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn create_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(body): Json<CreateOwnCertRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.ownnm.trim().is_empty() {
        return Err(AppError::BadRequest("Certificate name cannot be empty".to_string()));
    }
    if !is_valid_status(&body.ownst) {
        return Err(AppError::BadRequest(
            "Invalid status: must be studying, passed, failed, or abandoned".to_string(),
        ));
    }

    // Upsert the cert name into TBL_CERMAS if not already present
    let cert_id = if let Some(ownce) = body.ownce {
        Some(ownce)
    } else {
        // Try to find or create a master cert entry by name
        let existing = sqlx::query!(
            "SELECT cerid FROM TBL_CERMAS WHERE cernm = $1",
            body.ownnm.trim()
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

        if let Some(row) = existing {
            Some(row.cerid)
        } else {
            let new_cerid = Uuid::new_v4();
            let now = Utc::now();
            sqlx::query!(
                "INSERT INTO TBL_CERMAS (cerid, cernm, certm) VALUES ($1, $2, $3) ON CONFLICT (cernm) DO NOTHING",
                new_cerid,
                body.ownnm.trim(),
                now
            )
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

            // Fetch the actual cerid (in case ON CONFLICT fired)
            let row = sqlx::query!(
                "SELECT cerid FROM TBL_CERMAS WHERE cernm = $1",
                body.ownnm.trim()
            )
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

            row.map(|r| r.cerid)
        }
    };

    let ownid = Uuid::new_v4();
    let now = Utc::now();

    let cert = sqlx::query!(
        r#"
        INSERT INTO TBL_OWNCER (ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup)
        VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9)
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
        ownid,
        auth_user.useid,
        body.ownnm.trim(),
        cert_id,
        body.ownst,
        body.owntg,
        body.ownhr,
        now,
        now
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result = json!({
        "ownid": cert.ownid,
        "ownus": cert.ownus,
        "ownnm": cert.ownnm,
        "ownce": cert.ownce,
        "ownst": cert.ownst,
        "owntg": cert.owntg,
        "ownhr": cert.ownhr,
        "ownfl": cert.ownfl,
        "owntm": cert.owntm,
        "ownup": cert.ownup,
    });

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn update_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOwnCertRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.ownnm.trim().is_empty() {
        return Err(AppError::BadRequest("Certificate name cannot be empty".to_string()));
    }
    if !is_valid_status(&body.ownst) {
        return Err(AppError::BadRequest(
            "Invalid status: must be studying, passed, failed, or abandoned".to_string(),
        ));
    }

    let now = Utc::now();

    let cert = sqlx::query!(
        r#"
        UPDATE TBL_OWNCER
        SET ownnm = $1, ownce = $2, ownst = $3, owntg = $4, ownhr = $5, ownup = $6
        WHERE ownid = $7 AND ownus = $8
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
        body.ownnm.trim(),
        body.ownce,
        body.ownst,
        body.owntg,
        body.ownhr,
        now,
        id,
        auth_user.useid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = json!({
        "ownid": cert.ownid,
        "ownus": cert.ownus,
        "ownnm": cert.ownnm,
        "ownce": cert.ownce,
        "ownst": cert.ownst,
        "owntg": cert.owntg,
        "ownhr": cert.ownhr,
        "ownfl": cert.ownfl,
        "owntm": cert.owntm,
        "ownup": cert.ownup,
    });

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn delete_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    // Only allow deletion if ownst = 'abandoned'
    let cert = sqlx::query!(
        "SELECT ownid, ownst FROM TBL_OWNCER WHERE ownid = $1 AND ownus = $2",
        id,
        auth_user.useid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    if cert.ownst != "abandoned" {
        return Err(AppError::BadRequest(
            "Only abandoned certificates can be deleted".to_string(),
        ));
    }

    sqlx::query!(
        "DELETE FROM TBL_OWNCER WHERE ownid = $1 AND ownus = $2",
        id,
        auth_user.useid
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    Ok(Json(json!({"data": null, "error": null})))
}

pub async fn update_hours(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<HoursRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.delta.is_none() && body.value.is_none() {
        return Err(AppError::BadRequest(
            "Either delta or value must be provided".to_string(),
        ));
    }

    let now = Utc::now();

    let cert = if let Some(value) = body.value {
        if value < 0.0 {
            return Err(AppError::BadRequest("Hours cannot be negative".to_string()));
        }
        // Set directly
        sqlx::query!(
            r#"
            UPDATE TBL_OWNCER
            SET ownhr = $1, ownup = $2
            WHERE ownid = $3 AND ownus = $4
            RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
            "#,
            value,
            now,
            id,
            auth_user.useid
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?
    } else if let Some(delta) = body.delta {
        // Add delta, clamping to >= 0
        sqlx::query!(
            r#"
            UPDATE TBL_OWNCER
            SET ownhr = GREATEST(0, COALESCE(ownhr, 0) + $1), ownup = $2
            WHERE ownid = $3 AND ownus = $4
            RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
            "#,
            delta,
            now,
            id,
            auth_user.useid
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?
    } else {
        unreachable!()
    };

    let result = json!({
        "ownid": cert.ownid,
        "ownus": cert.ownus,
        "ownnm": cert.ownnm,
        "ownce": cert.ownce,
        "ownst": cert.ownst,
        "owntg": cert.owntg,
        "ownhr": cert.ownhr,
        "ownfl": cert.ownfl,
        "owntm": cert.owntm,
        "ownup": cert.ownup,
    });

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn abandon_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let now = Utc::now();

    let cert = sqlx::query!(
        r#"
        UPDATE TBL_OWNCER
        SET ownst = 'abandoned', ownup = $1
        WHERE ownid = $2 AND ownus = $3
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
        now,
        id,
        auth_user.useid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = json!({
        "ownid": cert.ownid,
        "ownus": cert.ownus,
        "ownnm": cert.ownnm,
        "ownce": cert.ownce,
        "ownst": cert.ownst,
        "owntg": cert.owntg,
        "ownhr": cert.ownhr,
        "ownfl": cert.ownfl,
        "owntm": cert.owntm,
        "ownup": cert.ownup,
    });

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn restore_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let now = Utc::now();

    let cert = sqlx::query!(
        r#"
        UPDATE TBL_OWNCER
        SET ownst = 'studying', ownup = $1
        WHERE ownid = $2 AND ownus = $3
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
        now,
        id,
        auth_user.useid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = json!({
        "ownid": cert.ownid,
        "ownus": cert.ownus,
        "ownnm": cert.ownnm,
        "ownce": cert.ownce,
        "ownst": cert.ownst,
        "owntg": cert.owntg,
        "ownhr": cert.ownhr,
        "ownfl": cert.ownfl,
        "owntm": cert.owntm,
        "ownup": cert.ownup,
    });

    Ok(Json(json!({"data": result, "error": null})))
}
