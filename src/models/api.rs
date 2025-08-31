use crate::db::get_global_pool;
use serde::Serialize;
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct APIFilters {
    pub threat_filters: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct APIRules {
    pub threat_filters: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct APIFilterConfig {
    pub apiname: String,
    pub apikey: String,
    pub apidesc: Option<String>,
    pub endpoint_url: String,
    pub auth_type: Option<String>,
    pub allowed_ip: Option<String>,
    pub rate_limit: Option<String>,
    pub threat_filters: Option<String>,
    pub alert_email: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
}

pub async fn insert_api(
    apiname: &str,
    apikey: &str,
    apidesc: &str,
    endpoint_url: &str,
    auth_type: &str,
    allowed_ip: &str,
    rate_limit: &str,
    threat_filters: &str,
    alert_email: &str,
) -> Result<(), Error> {
    let pool = get_global_pool();
    sqlx::query(
        r#"
        INSERT INTO api (
            apiname, apikey, apidesc, endpoint_url,
            auth_type, allowed_ip, rate_limit,
            threat_filters, alert_email
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(apiname)
    .bind(apikey)
    .bind(apidesc)
    .bind(endpoint_url)
    .bind(auth_type)
    .bind(allowed_ip)
    .bind(rate_limit)
    .bind(threat_filters)
    .bind(alert_email)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn retrieve_apikey(apiname: &str) -> Result<String, Error> {
    let pool = get_global_pool();
    let data = sqlx::query("SELECT apikey FROM api WHERE apiname = $1")
        .bind(apiname)
        .fetch_one(pool)
        .await?;
    let api_key: String = data.try_get("apikey")?;
    Ok(api_key)
}

pub async fn retrieve_predefined_filters(apiname: &str) -> Result<Option<APIFilterConfig>, Error> {
    let pool = get_global_pool();

    let rec = sqlx::query_as::<_, APIFilterConfig>(
        r#"
        SELECT 
            apiname, 
            apikey, 
            apidesc, 
            endpoint_url, 
            auth_type, 
            allowed_ip, 
            rate_limit, 
            threat_filters, 
            alert_email, 
            created_at
        FROM api 
        WHERE apiname = $1
        "#,
    )
    .bind(apiname)
    .fetch_optional(pool)
    .await?;

    Ok(rec)
}

pub async fn retrieve_email_from_api(apiname: &str) -> Result<String, Error> {
    let pool = get_global_pool();
    let res = sqlx::query(r#" select alert_email from api where apiname=$1"#)
        .bind(apiname)
        .fetch_one(pool)
        .await?;
    let email = res.try_get("alert_email")?;
    Ok(email)
}

pub async fn retrieve_api_isactive(apiname: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let res = sqlx::query(r#" select active_status from api where apiname=$1"#)
        .bind(apiname)
        .fetch_one(pool)
        .await?;
    let status = res.try_get("active_status")?;
    Ok(status)
}

pub async fn retrieve_apifilters(alert_email: &str) -> Result<Option<APIFilters>, Error> {
    let pool = get_global_pool();
    let data = sqlx::query_as::<_, APIFilters>(
        r#"
        select threat_filters from api where alert_email = $1
        "#,
    )
    .bind(alert_email)
    .fetch_optional(pool)
    .await?;
    Ok(data)
}

pub async fn update_api_filters(apiname: &str, threat_filters: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let res = sqlx::query(r#"update api set threat_filters = $1 where apiname=$2"#)
        .bind(threat_filters)
        .bind(apiname)
        .execute(pool)
        .await?;

    Ok(res.rows_affected() > 0)
}

pub async fn check_api_exists(apiname: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let sql = sqlx::query(r#"select apiname from request_logs where apiname=$1"#)
        .bind(apiname)
        .execute(pool)
        .await?;

    Ok(sql.rows_affected() > 0)
}

pub async fn disable_api(apiname: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" update api set active_status=$1 where apiname=$2"#)
        .bind(false)
        .bind(apiname)
        .execute(pool)
        .await?;
    Ok(query.rows_affected() > 0)
}

pub async fn enable_api(apiname: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" update api set active_status=$1 where apiname=$2"#)
        .bind(true)
        .bind(apiname)
        .execute(pool)
        .await?;
    Ok(query.rows_affected() > 0)
}

pub async fn delete_api(apiname: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" delete from api where apiname=$2"#)
        .bind(true)
        .bind(apiname)
        .execute(pool)
        .await?;
    Ok(query.rows_affected() > 0)
}

pub async fn regenerate_api_key_req(apiname: &str, apikey: &str) -> Result<bool, Error> {
    let pool = get_global_pool();
    let query = sqlx::query(r#" update api set apikey = $1 where apiname = $2"#)
        .bind(apikey)
        .bind(apiname)
        .execute(pool)
        .await?;

    Ok(query.rows_affected() > 0)
}
