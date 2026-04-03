use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CertMaster {
    pub cerid: Uuid,
    pub cernm: String,
    pub cerct: Option<String>,
    pub certm: DateTime<Utc>,
}
