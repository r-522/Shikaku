use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Favorite {
    pub favid: Uuid,
    pub favus: Uuid,
    pub favtg: Uuid,
    pub favtm: DateTime<Utc>,
}
