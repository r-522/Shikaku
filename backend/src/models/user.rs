use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub useid: Uuid,
    pub usenm: String,
    pub useml: String,
    #[serde(skip_serializing)]
    pub usepw: String,
    pub usetm: DateTime<Utc>,
    pub useup: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub useid: Uuid,
    pub usenm: String,
    pub useml: String,
    pub usetm: DateTime<Utc>,
    pub useup: DateTime<Utc>,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        UserPublic {
            useid: u.useid,
            usenm: u.usenm,
            useml: u.useml,
            usetm: u.usetm,
            useup: u.useup,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserWithStats {
    pub useid: Uuid,
    pub usenm: String,
    pub cert_count: Option<i64>,
    pub passed_count: Option<i64>,
    pub is_favorite: Option<bool>,
}
