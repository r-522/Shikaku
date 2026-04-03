use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::{
    errors::AppError,
    middleware::auth::JwtClaims,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn build_session_cookie(token: &str, secure: bool) -> Cookie<'static> {
    Cookie::build(("shikaku_session", token.to_string()))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::days(30))
        .path("/")
        .build()
}

fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build(("shikaku_session", ""))
        .http_only(true)
        .secure(false)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .path("/")
        .build()
}

async fn create_session_token(
    state: &AppState,
    user_id: Uuid,
) -> Result<String, AppError> {
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    let exp = (now + chrono::Duration::days(30)).timestamp();

    let claims = JwtClaims {
        sub: user_id.to_string(),
        exp,
        jti: session_id.to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encode error: {}", e)))?;

    let expires_at = chrono::DateTime::<Utc>::from_timestamp(exp, 0)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Invalid timestamp")))?;

    sqlx::query_unchecked!(
        "INSERT INTO TBL_SESSION (sesid, sesus, sestk, sesex, sestm) VALUES ($1, $2, $3, $4, $5)",
        session_id,
        user_id,
        token,
        expires_at,
        now
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    Ok(token)
}

pub async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !is_valid_email(&body.email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }
    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }
    if body.username.trim().is_empty() {
        return Err(AppError::BadRequest("Username cannot be empty".to_string()));
    }

    let existing = sqlx::query_unchecked!("SELECT useid FROM TBL_USER WHERE useml = $1", body.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    if existing.is_some() {
        return Err(AppError::Conflict("Email already in use".to_string()));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing error: {}", e)))?
        .to_string();

    let user_id = Uuid::new_v4();
    let now = Utc::now();

    let user = sqlx::query_unchecked!(
        "INSERT INTO TBL_USER (useid, usenm, useml, usepw, usetm, useup) VALUES ($1, $2, $3, $4, $5, $6) RETURNING useid, usenm, useml, usetm, useup",
        user_id,
        body.username.trim(),
        body.email.to_lowercase(),
        password_hash,
        now,
        now
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

    let token = create_session_token(&state, user_id).await?;

    let user_public = serde_json::json!({
        "useid": user.useid,
        "usenm": user.usenm,
        "useml": user.useml,
        "usetm": user.usetm,
        "useup": user.useup,
    });

    let cookie = build_session_cookie(&token, state.config.cookie_secure);
    let mut response = Json(json!({"data": user_public, "error": null})).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

    Ok(response)
}

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.email.trim().is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("Email and password are required".to_string()));
    }

    let user = sqlx::query_unchecked!(
        "SELECT useid, usenm, useml, usepw, usetm, useup FROM TBL_USER WHERE useml = $1",
        body.email.to_lowercase()
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
    .ok_or_else(|| AppError::Unauthorized)?;

    let parsed_hash = PasswordHash::new(&user.usepw)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hash parse error: {}", e)))?;

    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Unauthorized)?;

    let token = create_session_token(&state, user.useid).await?;

    let user_public = serde_json::json!({
        "useid": user.useid,
        "usenm": user.usenm,
        "useml": user.useml,
        "usetm": user.usetm,
        "useup": user.useup,
    });

    let cookie = build_session_cookie(&token, state.config.cookie_secure);
    let mut response = Json(json!({"data": user_public, "error": null})).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

    Ok(response)
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    if let Some(cookie) = jar.get("shikaku_session") {
        let token = cookie.value().to_string();
        sqlx::query_unchecked!("DELETE FROM TBL_SESSION WHERE sestk = $1", token)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;
    }

    let clear_cookie = clear_session_cookie();
    let mut response = Json(json!({"data": null, "error": null})).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie.to_string()).unwrap(),
    );

    Ok(response)
}

pub async fn me(
    State(_state): State<AppState>,
    auth_user: crate::middleware::auth::AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let user_public = serde_json::json!({
        "useid": auth_user.useid,
        "usenm": auth_user.usenm,
        "useml": auth_user.useml,
    });

    Ok(Json(json!({"data": user_public, "error": null})))
}
