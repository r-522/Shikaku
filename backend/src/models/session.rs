use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub sesid: Uuid,
    pub sesus: Uuid,
    pub sestk: String,
    pub sesex: DateTime<Utc>,
    pub sestm: DateTime<Utc>,
}
