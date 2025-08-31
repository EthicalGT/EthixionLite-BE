use crate::db::get_global_pool;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Deserialize, Debug, FromRow, Serialize)]
pub struct encData {
    pub id: i32,
    pub apiname: String,
    pub owner_email: String,
    pub aes_key: String,
    pub created_at: Option<NaiveDateTime>,
}

pub async fn make_api_enc_key_call(
    apiname: &str,
    owner_email: &str,
    aes_key: &str,
) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(
        r#"insert into api_enc_data_key(apiname, owner_email, aes_key) values($1,$2,$3)"#,
    )
    .bind(apiname)
    .bind(owner_email)
    .bind(aes_key)
    .execute(pool)
    .await?;

    Ok(true)
}

pub async fn get_api_enc_key(apiname: &str, owner_email: &str) -> Result<encData, Error> {
    let pool = get_global_pool();
    let data = sqlx::query_as::<_, encData>(
        r#"select * from api_enc_data_key where apiname=$1 and owner_email=$2"#,
    )
    .bind(apiname)
    .bind(owner_email)
    .fetch_one(pool)
    .await?;

    Ok(data)
}
