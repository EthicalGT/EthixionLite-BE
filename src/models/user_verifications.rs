use crate::db::get_global_pool;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Deserialize, Debug, FromRow, Serialize)]
pub struct verificationData {
    pub email: String,
    pub token: String,
    pub created_at: Option<NaiveDateTime>,
}

pub async fn make_user_verification(email: &str, token: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" insert into user_verifications(email, token) values($1, $2)"#)
        .bind(email)
        .bind(token)
        .execute(pool)
        .await?;

    Ok(true)
}

pub async fn get_verification_data(token: &str) -> Result<Option<verificationData>, Error> {
    let pool = get_global_pool();
    let expiry = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(5);

    // Log the inputs
    println!("[DEBUG] Checking verification for token: {}", token);
    println!("[DEBUG] Expiry threshold: {}", expiry);

    let query = sqlx::query_as::<_, verificationData>(
        r#"
        SELECT * 
        FROM user_verifications 
        WHERE token = $1 
          AND created_at >= $2 
        LIMIT 1
        "#,
    )
    .bind(token)
    .bind(expiry)
    .fetch_optional(pool)
    .await?;

    // Log the result
    match &query {
        Some(v) => println!("[DEBUG] Found verification record: {:?}", v),
        None => println!("[DEBUG] No matching record found."),
    }

    Ok(query)
}
