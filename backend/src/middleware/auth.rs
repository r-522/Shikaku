use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::AppError, AppState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub useid: Uuid,
    pub usenm: String,
    pub useml: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized)?;

        let token = jar
            .get("shikaku_session")
            .map(|c| c.value().to_string())
            .ok_or(AppError::Unauthorized)?;

        let claims = decode::<JwtClaims>(
            &token,
            &DecodingKey::from_secret(app_state.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?
        .claims;

        let session_id = Uuid::parse_str(&claims.jti).map_err(|_| AppError::Unauthorized)?;

        let session = sqlx::query_unchecked!(
            "SELECT sesid FROM TBL_SESSION WHERE sesid = $1 AND sestk = $2 AND sesex > NOW()",
            session_id,
            token
        )
        .fetch_optional(&app_state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?;

        if session.is_none() {
            return Err(AppError::Unauthorized);
        }

        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;

        let user = sqlx::query_unchecked!(
            "SELECT useid, usenm, useml FROM TBL_USER WHERE useid = $1",
            user_id
        )
        .fetch_optional(&app_state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::from(e)))?
        .ok_or(AppError::Unauthorized)?;

        Ok(AuthUser {
            useid: user.useid,
            usenm: user.usenm,
            useml: user.useml,
        })
    }
}
