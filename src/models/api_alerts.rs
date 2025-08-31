use crate::db::get_global_pool;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct APIAlert {
    pub alert_id: i32,
    pub user_email: String,
    pub apiname: String,
    pub request_id: String,
    pub alert_type: Vec<String>,
    pub severity: Vec<String>,
    pub message: Vec<String>,
    pub status: Option<String>,
    pub created_at: Option<NaiveDateTime>,
}

pub async fn insert_api_alert(
    user_email: &str,
    apiname: &str,
    request_id: &str,
    alert_type: &Vec<String>,
    severity: &Vec<String>,
    message: &Vec<String>,
    status: &str,
) -> Result<(), Error> {
    let pool = get_global_pool();
    sqlx::query(
        r#"
        INSERT INTO api_alerts (
            user_email, apiname, request_id, alert_type, severity, message,
            status
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(user_email)
    .bind(apiname)
    .bind(request_id)
    .bind(alert_type)
    .bind(severity)
    .bind(message)
    .bind(status)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn retrieve_api_alerts(email: &str) -> Result<Vec<APIAlert>, Error> {
    let pool = get_global_pool();
    let query = sqlx::query_as::<_, APIAlert>(r#" select * from api_alerts where user_email=$1"#)
        .bind(email)
        .fetch_all(pool)
        .await?;

    Ok(query)
}
