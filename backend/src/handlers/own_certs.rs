use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use sqlx::{postgres::PgRow, Row};
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

fn own_cert_row_to_json(c: &PgRow) -> serde_json::Value {
    json!({
        "ownid": c.try_get::<Uuid, _>("ownid").ok(),
        "ownus": c.try_get::<Uuid, _>("ownus").ok(),
        "ownnm": c.try_get::<String, _>("ownnm").ok(),
        "ownce": c.try_get::<Option<Uuid>, _>("ownce").ok().flatten(),
        "ownst": c.try_get::<String, _>("ownst").ok(),
        "owntg": c.try_get::<Option<chrono::NaiveDate>, _>("owntg").ok().flatten(),
        "ownhr": c.try_get::<Option<f64>, _>("ownhr").ok().flatten(),
        "ownfl": c.try_get::<bool, _>("ownfl").ok(),
        "owntm": c.try_get::<chrono::DateTime<Utc>, _>("owntm").ok(),
        "ownup": c.try_get::<chrono::DateTime<Utc>, _>("ownup").ok(),
    })
}

pub async fn list_own_certs(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let certs = sqlx::query(
        r#"
        SELECT ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        FROM TBL_OWNCER
        WHERE ownus = $1 AND ownfl = false
        ORDER BY owntm DESC
        "#,
    )
    .bind(auth_user.useid)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result: Vec<serde_json::Value> = certs
        .into_iter()
        .map(|c| own_cert_row_to_json(&c))
        .collect();

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn create_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(body): Json<CreateOwnCertRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.ownnm.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Certificate name cannot be empty".to_string(),
        ));
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
        let existing = sqlx::query("SELECT cerid FROM TBL_CERMAS WHERE cernm = $1")
            .bind(body.ownnm.trim())
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

        if let Some(row) = existing {
            Some(
                row.try_get("cerid")
                    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?,
            )
        } else {
            let new_cerid = Uuid::new_v4();
            let now = Utc::now();
            sqlx::query("INSERT INTO TBL_CERMAS (cerid, cernm, certm) VALUES ($1, $2, $3) ON CONFLICT (cernm) DO NOTHING")
            .bind(new_cerid)
            .bind(body.ownnm.trim())
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

            // Fetch the actual cerid (in case ON CONFLICT fired)
            let row = sqlx::query("SELECT cerid FROM TBL_CERMAS WHERE cernm = $1")
                .bind(body.ownnm.trim())
                .fetch_optional(&state.db)
                .await
                .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

            row.map(|r| r.try_get("cerid").ok()).flatten()
        }
    };

    let ownid = Uuid::new_v4();
    let now = Utc::now();

    let cert = sqlx::query(
        r#"
        INSERT INTO TBL_OWNCER (ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup)
        VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9)
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
    )
    .bind(ownid)
    .bind(auth_user.useid)
    .bind(body.ownnm.trim())
    .bind(cert_id)
    .bind(&body.ownst)
    .bind(body.owntg)
    .bind(body.ownhr)
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let result = own_cert_row_to_json(&cert);

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn update_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOwnCertRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.ownnm.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Certificate name cannot be empty".to_string(),
        ));
    }
    if !is_valid_status(&body.ownst) {
        return Err(AppError::BadRequest(
            "Invalid status: must be studying, passed, failed, or abandoned".to_string(),
        ));
    }

    let now = Utc::now();

    let cert = sqlx::query(
        r#"
        UPDATE TBL_OWNCER
        SET ownnm = $1, ownce = $2, ownst = $3, owntg = $4, ownhr = $5, ownup = $6
        WHERE ownid = $7 AND ownus = $8
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
    )
    .bind(body.ownnm.trim())
    .bind(body.ownce)
    .bind(&body.ownst)
    .bind(body.owntg)
    .bind(body.ownhr)
    .bind(now)
    .bind(id)
    .bind(auth_user.useid)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = own_cert_row_to_json(&cert);

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn delete_own_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    // Only allow deletion if ownst = 'abandoned'
    let cert = sqlx::query("SELECT ownid, ownst FROM TBL_OWNCER WHERE ownid = $1 AND ownus = $2")
        .bind(id)
        .bind(auth_user.useid)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or_else(|| {
            AppError::NotFound("Certificate not found or not owned by you".to_string())
        })?;

    if cert
        .try_get::<String, _>("ownst")
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        != "abandoned"
    {
        return Err(AppError::BadRequest(
            "Only abandoned certificates can be deleted".to_string(),
        ));
    }

    sqlx::query("DELETE FROM TBL_OWNCER WHERE ownid = $1 AND ownus = $2")
        .bind(id)
        .bind(auth_user.useid)
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
        sqlx::query(
            r#"
            UPDATE TBL_OWNCER
            SET ownhr = $1, ownup = $2
            WHERE ownid = $3 AND ownus = $4
            RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
            "#,
        )
        .bind(value)
        .bind(now)
        .bind(id)
        .bind(auth_user.useid)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or_else(|| {
            AppError::NotFound("Certificate not found or not owned by you".to_string())
        })?
    } else if let Some(delta) = body.delta {
        // Add delta, clamping to >= 0
        sqlx::query(
            r#"
            UPDATE TBL_OWNCER
            SET ownhr = GREATEST(0, COALESCE(ownhr, 0) + $1), ownup = $2
            WHERE ownid = $3 AND ownus = $4
            RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
            "#,
        )
        .bind(delta)
        .bind(now)
        .bind(id)
        .bind(auth_user.useid)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or_else(|| {
            AppError::NotFound("Certificate not found or not owned by you".to_string())
        })?
    } else {
        unreachable!()
    };

    let result = own_cert_row_to_json(&cert);

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn abandon_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let now = Utc::now();

    let cert = sqlx::query(
        r#"
        UPDATE TBL_OWNCER
        SET ownst = 'abandoned', ownup = $1
        WHERE ownid = $2 AND ownus = $3
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
    )
    .bind(now)
    .bind(id)
    .bind(auth_user.useid)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = own_cert_row_to_json(&cert);

    Ok(Json(json!({"data": result, "error": null})))
}

pub async fn restore_cert(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let now = Utc::now();

    let cert = sqlx::query(
        r#"
        UPDATE TBL_OWNCER
        SET ownst = 'studying', ownup = $1
        WHERE ownid = $2 AND ownus = $3
        RETURNING ownid, ownus, ownnm, ownce, ownst, owntg, ownhr, ownfl, owntm, ownup
        "#,
    )
    .bind(now)
    .bind(id)
    .bind(auth_user.useid)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::NotFound("Certificate not found or not owned by you".to_string()))?;

    let result = own_cert_row_to_json(&cert);

    Ok(Json(json!({"data": result, "error": null})))
}
