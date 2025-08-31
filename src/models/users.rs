use crate::db::get_global_pool;
use chrono::{DateTime, Utc};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Debug, FromRow)]
pub struct UserData {
    pub fullname: String,
    pub email: String,
    pub password: String,
    pub registered_on: DateTime<Utc>,
    pub login_status: bool,
}

pub async fn insert_user(
    fullname: &str,
    email: &str,
    password: &str,
    ustatus: &bool,
) -> Result<(), Error> {
    let pool = get_global_pool();
    sqlx::query(
        r#"
        INSERT INTO users (fullname, email, password, registered_on, login_status)
        VALUES ($1, $2, $3, NOW(), $4)
        "#,
    )
    .bind(fullname)
    .bind(email)
    .bind(password)
    .bind(ustatus)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn retreive_pwd(email: &str) -> Result<String, Error> {
    let pool = get_global_pool();
    let data = sqlx::query("SELECT password FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await?;
    let pwd: String = data.try_get("password")?;
    Ok(pwd)
}
pub async fn retrieve_current_user_info(email: &str) -> Result<UserData, Error> {
    let pool: &'static Pool<Postgres> = get_global_pool();
    let data: UserData =
        sqlx::query_as::<_, UserData>("select * from users where email=$1 and status='verified'")
            .bind(email)
            .fetch_one(pool)
            .await?;
    Ok(data)
}
pub async fn update_loggedin_status(email: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let mut tx = pool.begin().await?;

    sqlx::query("UPDATE users SET login_status = $1 WHERE email = $2")
        .bind(true)
        .bind(email)
        .execute(&mut *tx)
        .await?;

    sqlx::query("UPDATE users SET login_status = $1 WHERE email != $2")
        .bind(false)
        .bind(email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(true)
}

pub async fn google_login(email: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let res = sqlx::query(r#" select 1 from users where email=$1 and status='verified' limit 1"#)
        .bind(email)
        .fetch_optional(pool)
        .await?;

    Ok(res.is_some())
}

pub async fn update_verified_status(email: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" update users set status='verified' where email=$1 "#)
        .bind(email)
        .execute(pool)
        .await?;

    Ok(query.rows_affected() > 0)
}
