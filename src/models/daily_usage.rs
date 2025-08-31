use crate::db::get_global_pool;
use chrono::NaiveDate;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct DailyUsage {
    pub user_email: String,
    pub api_name: String,
    pub request_date: Option<NaiveDate>,
    pub request_count: i32,
}

pub async fn map_api_daily_usage(user_email: &str, api_name: &str) -> Result<i64, Error> {
    let pool = get_global_pool();
    let record: (i64,) = sqlx::query_as(
        r#"
        INSERT INTO daily_usage (email, api_name, request_date, request_count)
VALUES ($1, $2, CURRENT_DATE, 1)
ON CONFLICT (email, api_name, request_date)
DO UPDATE 
SET request_count = daily_usage.request_count + 1
RETURNING request_count;

        "#,
    )
    .bind(user_email)
    .bind(api_name)
    .fetch_one(pool)
    .await?;

    Ok(record.0)
}
