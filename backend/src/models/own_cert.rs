use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OwnCert {
    pub ownid: Uuid,
    pub ownus: Uuid,
    pub ownnm: String,
    pub ownce: Option<Uuid>,
    pub ownst: String,
    pub owntg: Option<NaiveDate>,
    pub ownhr: Option<f64>,
    pub ownfl: bool,
    pub owntm: DateTime<Utc>,
    pub ownup: DateTime<Utc>,
}
