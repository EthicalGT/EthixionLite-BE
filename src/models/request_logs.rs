use crate::db::get_global_pool;
use chrono::{DateTime, Utc};
use chrono::{NaiveDate, NaiveDateTime};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{pool, postgres::PgRow, Error, FromRow, Pool, Postgres, Row};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::try_join;

fn parse_ip(ip_str: &str) -> IpAddr {
    IpAddr::from_str(ip_str).unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct threatLogs {
    pub apiname: String,
    pub threats: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct dashboardData {
    pub totalReq: String,
    pub allowedReq: String,
    pub blockedReq: String,
    pub suspiciousReq: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RequestLog {
    pub request_id: String,
    pub user_email: String,
    pub apiname: String,
    pub origin_url: String,
    pub redirect_url: String,
    pub status: bool,
    pub threats: Vec<String>,
    pub ip_address: std::net::IpAddr,
    pub user_agent: String,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub detected_threats: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct SecurityDashboardResponse {
    pub total_detected_threats: i64,
    pub top_threat_types: Vec<ThreatTypeCount>,
    pub threats_per_api: Vec<ThreatPerAPIEntry>,
    pub blocked_request_count: i64,
    pub blocked_requests_over_time: Vec<CountOverTime>,
    pub suspicious_ips: Vec<SuspiciousIPEntry>,
    pub threats_over_time: Vec<CountOverTime>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ThreatTypeCount {
    pub threat: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ThreatPerAPIEntry {
    pub apiname: Option<String>,
    pub threat: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CountOverTime {
    pub date: chrono::NaiveDate,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SuspiciousIPEntry {
    pub ip_address: String,
    pub total_threats: i64,
    pub blocked_requests: i64,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserActivityTimeline {
    pub day: NaiveDate,
    pub user_email: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserAgentCount {
    pub user_agent: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct HourlyTraffic {
    pub hour: chrono::DateTime<chrono::Utc>,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct DayOfWeekTraffic {
    pub day_of_week: i32,
    pub count: i64,
}
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct GeoDistributionEntry {
    pub ip_address: Option<IpAddr>,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemTrendResponse {
    pub user_activity: Vec<UserActivityTimeline>,
    pub user_agents: Vec<UserAgentCount>,
    pub peak_traffic: Vec<HourlyTraffic>,
    pub weekday_traffic: Vec<DayOfWeekTraffic>,
    pub geo_distribution: Vec<GeoDistributionEntry>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct StatusCount {
    pub status: Option<bool>,
    pub count: i64,
}

#[derive(Debug, Serialize, FromRow)]
pub struct APIStatusStats {
    pub apiname: Option<String>,
    pub success: i64,
    pub failure: i64,
}

#[derive(Debug, Serialize, FromRow)]
pub struct FailureTimeline {
    pub date: Option<chrono::NaiveDate>,
    pub failures: i64,
}

#[derive(Debug, Serialize)]
pub struct StatusTrendResponse {
    pub status_pie: Vec<StatusCount>,
    pub api_status_breakdown: Vec<APIStatusStats>,
    pub failure_timeline: Vec<FailureTimeline>,
}
#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct ApiThreatHeatmap {
    pub apiname: String,
    pub total_requests: i64,
    pub threat_count: i64,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct SuccessRateEntry {
    pub ip_address: String,
    pub apiname: String,
    pub success: i64,
    pub failure: i64,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct AbusiveEntry {
    pub ip_address: String,
    pub fail_count: i64,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct AbuseRatePattern {
    pub ip_address: String,
    pub apiname: String,
    pub count: i64,
    pub start_time: chrono::NaiveDateTime,
    pub end_time: chrono::NaiveDateTime,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdvancedMonitorResponse {
    pub api_threat_heatmap: Vec<ApiThreatHeatmap>,
    pub success_rate_data: Vec<SuccessRateEntry>,
    pub flagged_abuse: Vec<AbusiveEntry>,
    pub rate_limit_alerts: Vec<AbuseRatePattern>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct APINames {
    pub apiname: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct APIEndpoint {
    pub apiname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct APIRecord {
    pub apiname: String,
    pub endpoint: String,
    pub createdon: NaiveDateTime,
    pub last_used: String,
    pub total_req: i64,
    pub threats_blocked: Vec<String>,
    pub active_status: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct APIData {
    pub apis: Vec<APIRecord>,
}

#[derive(Debug, FromRow)]
struct APIRow {
    pub apiname: String,
    pub endpoint_url: String,
    pub created_at: NaiveDateTime,
    pub active_status: bool,
}

#[derive(Deserialize)]
pub struct APIURLHeaders {
    pub apiname: String,
    pub apikey: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub user_agent: String,
    pub host: String,
    pub referer: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub total_headers: usize,
    pub suspicious: bool,
    pub matched_pattern: Option<String>,
    pub redirect_url: String,
    pub origin_url: String,
}

pub struct PrechecksHeaders {
    pub apiname: String,
    pub apikey: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub user_agent: String,
    pub host: String,
    pub referer: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub total_headers: usize,
    pub suspicious: bool,
    pub matched_pattern: Option<String>,
    pub redirect_url: String,
    pub origin_url: String,
    pub body: String,
    pub user: String,
    pub ip_risk_score: i32,
    pub rate_limit_exceeded: bool,
}

pub struct APIRequestInfo {
    pub headers: APIURLHeaders,
}

pub async fn make_request_log(
    request_id: &str,
    user_email: &str,
    apiname: &str,
    origin_url: &str,
    redirect_url: &str,
    status: bool,
    threats: Vec<String>,
    ip_address: &str,
    user_agent: &str,
    detected_threats: &Vec<String>,
) -> Result<bool, sqlx::Error> {
    let pool = get_global_pool();
    let query = r#"
    INSERT INTO request_logs (
        request_id,
        user_email,
        apiname,
        origin_url,
        redirect_url,
        status,
        threats,
        ip_address,
        user_agent,
        timestamp,
        detected_threats
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11)
"#;

    let res = sqlx::query(query)
        .bind(request_id)
        .bind(user_email)
        .bind(apiname)
        .bind(origin_url)
        .bind(redirect_url)
        .bind(status)
        .bind(threats)
        .bind(ip_address)
        .bind(user_agent)
        .bind(chrono::Utc::now())
        .bind(detected_threats)
        .execute(pool)
        .await?;

    Ok(res.rows_affected() == 1)
}

pub async fn retrieve_request_logs(email: &str) -> Result<Vec<threatLogs>, Error> {
    let pool = get_global_pool();
    let query = sqlx::query_as::<_, threatLogs>(r#"select apiname, threats from request_logs where user_email = $1 and date(timestamp)=current_date"#)
    .bind(email)
    .bind(false)
    .fetch_all(pool)
    .await?;

    Ok(query)
}

pub async fn get_dashboard_data(email: &str) -> Result<Option<dashboardData>, Error> {
    let pool = get_global_pool();
    let query1 = sqlx::query_scalar::<_, i64>(
        r#"select count(timestamp) as count from request_logs where user_email = $1"#,
    )
    .bind(email)
    .fetch_optional(pool);

    let query2 = sqlx::query_scalar::<_, i64>(
        r#"select count(*) from request_logs where user_email = $1 and status = $2 "#,
    )
    .bind(email)
    .bind(true)
    .fetch_optional(pool);

    let query3 = sqlx::query_scalar::<_, i64>(
        r#"select count(status) from request_logs where status=$1 and user_email = $2"#,
    )
    .bind(false)
    .bind(email)
    .fetch_optional(pool);

    let query4 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) 
FROM request_logs
WHERE user_email = $1
  AND status = false
  AND cardinality(detected_threats) > 0;
"#,
    )
    .bind(email)
    .fetch_optional(pool);

    let (totalRq, allowedRq, blockedRq, suspiciousRq) = try_join!(query1, query2, query3, query4)?;

    Ok(Some(dashboardData {
        totalReq: totalRq.expect("Failed to parse!").to_string(),
        allowedReq: allowedRq.expect("Failed to parse!").to_string(),
        blockedReq: blockedRq.expect("Failed to parse!").to_string(),
        suspiciousReq: suspiciousRq.expect("Failed to parse!").to_string(),
    }))
}

pub async fn get_todays_stats(email: &str) -> Result<dashboardData, sqlx::Error> {
    let pool = get_global_pool();

    // Use COALESCE to ensure the query never returns NULL
    let query1 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COALESCE(COUNT(timestamp), 0) FROM request_logs WHERE date(timestamp) = current_date"#
    )
    .fetch_one(pool);

    let query2 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COALESCE(COUNT(*), 0) FROM request_logs WHERE user_email = $1 AND date(timestamp) = current_date AND status=true"#
    )
    .bind(email)
    .fetch_one(pool);

    let query3 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COALESCE(COUNT(status), 0) FROM request_logs WHERE status = false AND user_email = $1 AND date(timestamp) = current_date"#
    )
    .bind(email)
    .fetch_one(pool);

    let query4 = sqlx::query_scalar::<_, i64>(
        r#"SELECT COALESCE(SUM(cardinality(detected_threats)), 0) FROM request_logs WHERE date(timestamp) = current_date"#
    )
    .fetch_one(pool);

    // Run queries in parallel
    let (totalRq, allowedRq, blockedRq, suspiciousRq) =
        tokio::try_join!(query1, query2, query3, query4)?;

    println!(
        "DEBUG => totalRq: {}, allowedRq: {}, blockedRq: {}, suspiciousRq: {}",
        totalRq, allowedRq, blockedRq, suspiciousRq
    );

    Ok(dashboardData {
        totalReq: totalRq.to_string(),
        allowedReq: allowedRq.to_string(),
        blockedReq: blockedRq.to_string(),
        suspiciousReq: suspiciousRq.to_string(),
    })
}

pub async fn get_overall_report_logs(email: &str) -> Result<Vec<RequestLog>, Error> {
    let pool = get_global_pool();
    let data = sqlx::query_as::<_, RequestLog>(
        r#"SELECT
        request_id,
        user_email,
        apiname,
        origin_url,
        redirect_url,
        status,
        threats,
        ip_address,
        user_agent,
        timestamp,
        COALESCE(detected_threats, '{}'::text[]) AS detected_threats
    FROM request_logs
    WHERE user_email = $1
"#,
    )
    .bind(email)
    .fetch_all(pool)
    .await?;

    Ok(data)
}

pub async fn get_overall_stats(email: &str) -> Result<Option<dashboardData>, Error> {
    let pool = get_global_pool();
    let query1 = sqlx::query_scalar::<_, i64>(
        r#"select count(timestamp) as count from request_logs where user_email= $1"#,
    )
    .bind(email)
    .fetch_optional(pool);

    let query2 =
        sqlx::query_scalar::<_, i64>(r#"select count(*) from request_logs where user_email = $1"#)
            .bind(email)
            .fetch_optional(pool);

    let query3 = sqlx::query_scalar::<_, i64>(
        r#"select count(status) from request_logs where status=$1 and user_email = $2"#,
    )
    .bind(true)
    .bind(email)
    .fetch_optional(pool);
    let query4 = sqlx::query_scalar::<_,i64>(r#"SELECT
    SUM(cardinality(detected_threats)) AS total_detected_threats FROM request_logs where date(timestamp)=current_date"#).fetch_optional(pool);
    let (totalRq, allowedRq, blockedRq, supsiciousRq) = try_join!(query1, query2, query3, query4)?;

    println!(
        "DEBUG => totalRq: {:?}, allowedRq: {:?}, blockedRq: {:?}, suspiciousRq: {:?}",
        totalRq, allowedRq, blockedRq, supsiciousRq
    );

    Ok(Some(dashboardData {
        totalReq: totalRq.expect("Failed to parse!").to_string(),
        allowedReq: allowedRq.expect("Failed to parse!").to_string(),
        blockedReq: blockedRq.expect("Failed to parse!").to_string(),
        suspiciousReq: supsiciousRq.expect("Failed to parse!").to_string(),
    }))
}

pub async fn get_security_dashboard(email: &str) -> Result<SecurityDashboardResponse, sqlx::Error> {
    let pool = get_global_pool();

    // Prepare all futures
    let total_detected_threats_fut = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE(SUM(cardinality(detected_threats)), 0)
        FROM request_logs
        WHERE user_email = $1
        "#,
    )
    .bind(email)
    .fetch_one(pool);

    let top_threat_types_fut = sqlx::query_as::<_, ThreatTypeCount>(
        r#"
        SELECT threat, COUNT(*) AS count
        FROM (
            SELECT unnest(detected_threats) AS threat
            FROM request_logs
            WHERE user_email = $1
        ) sub
        GROUP BY threat
        ORDER BY count DESC
        LIMIT 10
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let threats_per_api_fut = sqlx::query_as::<_, ThreatPerAPIEntry>(
        r#"
        SELECT apiname, threat, COUNT(*) AS count
        FROM (
            SELECT apiname, unnest(detected_threats) AS threat
            FROM request_logs
            WHERE user_email = $1
        ) sub
        GROUP BY apiname, threat
        ORDER BY count DESC
        LIMIT 30
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let blocked_request_count_fut = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM request_logs
        WHERE user_email = $1 AND status = false
        "#,
    )
    .bind(email)
    .fetch_one(pool);

    let blocked_requests_over_time_fut = sqlx::query_as::<_, CountOverTime>(
        r#"
        SELECT DATE(timestamp) AS date, COUNT(*) AS count
        FROM request_logs
        WHERE user_email = $1 AND status = false
        GROUP BY date
        ORDER BY date
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let suspicious_ips_fut = sqlx::query_as::<_, SuspiciousIPEntry>(
        r#"
        SELECT ip_address::text AS ip_address,
               SUM(cardinality(detected_threats)) AS total_threats,
               COUNT(*) FILTER (WHERE status = false) AS blocked_requests
        FROM request_logs
        WHERE user_email = $1
        GROUP BY ip_address
        HAVING SUM(cardinality(detected_threats)) > 10 OR COUNT(*) FILTER (WHERE status = false) > 5
        ORDER BY total_threats DESC
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let threats_over_time_fut = sqlx::query_as::<_, CountOverTime>(
        r#"
        SELECT DATE(timestamp) AS date, SUM(cardinality(detected_threats)) AS count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY date
        ORDER BY date
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    // Run all queries concurrently
    let (
        total_detected_threats,
        top_threat_types,
        threats_per_api,
        blocked_request_count,
        blocked_requests_over_time,
        suspicious_ips,
        threats_over_time,
    ) = try_join!(
        total_detected_threats_fut,
        top_threat_types_fut,
        threats_per_api_fut,
        blocked_request_count_fut,
        blocked_requests_over_time_fut,
        suspicious_ips_fut,
        threats_over_time_fut
    )?;

    Ok(SecurityDashboardResponse {
        total_detected_threats,
        top_threat_types,
        threats_per_api,
        blocked_request_count,
        blocked_requests_over_time,
        suspicious_ips,
        threats_over_time,
    })
}

pub async fn get_system_trend_monitor(email: &str) -> Result<SystemTrendResponse, sqlx::Error> {
    let pool = get_global_pool();

    let user_activity_timeline_fut = sqlx::query_as::<_, UserActivityTimeline>(
        r#"
        SELECT DATE(timestamp) AS day, user_email, COUNT(*) AS count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY day, user_email
        ORDER BY day
        LIMIT 100
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let top_user_agents_fut = sqlx::query_as::<_, UserAgentCount>(
        r#"
        SELECT user_agent, COUNT(*) AS count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY user_agent
        ORDER BY count DESC
        LIMIT 10
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let hourly_traffic_fut = sqlx::query_as::<_, HourlyTraffic>(
        r#"
        SELECT date_trunc('hour', timestamp) AS hour, COUNT(*) AS count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY hour
        ORDER BY hour
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let requests_per_day_fut = sqlx::query_as::<_, DayOfWeekTraffic>(
        r#"
        SELECT EXTRACT(DOW FROM timestamp)::INT AS day_of_week, COUNT(*) AS count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY day_of_week
        ORDER BY day_of_week
       "#,
    )
    .bind(email)
    .fetch_all(pool);

    let geo_distribution = sqlx::query_as::<_, GeoDistributionEntry>(
        r#"
        SELECT ip_address, COUNT(*) AS count
    FROM request_logs
    WHERE user_email = $1
    GROUP BY ip_address
    ORDER BY count DESC
    LIMIT 20
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let (
        user_activity_timeline,
        top_user_agents,
        hourly_traffic,
        requests_per_day,
        geo_distribution,
    ) = try_join!(
        user_activity_timeline_fut,
        top_user_agents_fut,
        hourly_traffic_fut,
        requests_per_day_fut,
        geo_distribution
    )?;

    Ok(SystemTrendResponse {
        user_activity: user_activity_timeline,
        user_agents: top_user_agents,
        peak_traffic: hourly_traffic,
        weekday_traffic: requests_per_day,
        geo_distribution,
    })
}

pub async fn get_status_trend_monitor(email: &str) -> Result<StatusTrendResponse, sqlx::Error> {
    let pool = get_global_pool();

    let status_pie_fut = sqlx::query_as::<_, StatusCount>(
        r#"
        SELECT COALESCE(status, false) AS status, COUNT(*) AS count
FROM request_logs
WHERE user_email = $1
GROUP BY status
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let api_status_breakdown_fut = sqlx::query_as::<_, APIStatusStats>(
        r#"
        SELECT COALESCE(apiname, 'Unknown') AS apiname,
       COUNT(*) FILTER (WHERE status = true) AS success,
       COUNT(*) FILTER (WHERE status = false) AS failure
FROM request_logs
WHERE user_email = $1
GROUP BY apiname
ORDER BY failure DESC
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let failure_timeline_fut = sqlx::query_as::<_, FailureTimeline>(
        r#"
        SELECT COALESCE(DATE(timestamp), CURRENT_DATE) AS date, COUNT(*) AS failures
FROM request_logs
WHERE user_email = $1 AND status = false
GROUP BY date
ORDER BY date
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let (status_pie, api_status_breakdown, failure_timeline) = tokio::try_join!(
        status_pie_fut,
        api_status_breakdown_fut,
        failure_timeline_fut
    )?;

    Ok(StatusTrendResponse {
        status_pie,
        api_status_breakdown,
        failure_timeline,
    })
}

pub async fn get_advanced_monitors(email: &str) -> Result<AdvancedMonitorResponse, Error> {
    let pool = get_global_pool();

    let api_vs_threats_fut = sqlx::query_as::<_, ApiThreatHeatmap>(
        r#"
        SELECT apiname, COUNT(*) AS total_requests,
               SUM(CASE WHEN detected_threats IS NOT NULL AND array_length(detected_threats, 1) > 0 THEN 1 ELSE 0 END) AS threat_count
        FROM request_logs
        WHERE user_email = $1
        GROUP BY apiname
        ORDER BY threat_count DESC
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let success_rate_fut = sqlx::query_as::<_, SuccessRateEntry>(
        r#"
        SELECT ip_address::TEXT, apiname,
               COUNT(*) FILTER (WHERE status = true) AS success,
               COUNT(*) FILTER (WHERE status = false) AS failure
        FROM request_logs
        WHERE user_email = $1
        GROUP BY ip_address, apiname
        ORDER BY failure DESC
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let abusive_ips_fut = sqlx::query_as::<_, AbusiveEntry>(
        r#"
        SELECT ip_address::TEXT, COUNT(*) AS fail_count
        FROM request_logs
        WHERE user_email = $1 AND (status = false OR array_length(detected_threats, 1) > 0)
        GROUP BY ip_address
        HAVING COUNT(*) > 10
        ORDER BY fail_count DESC
        LIMIT 20
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let abusive_patterns_fut = sqlx::query_as::<_, AbuseRatePattern>(
        r#"
        SELECT ip_address::TEXT, apiname, COUNT(*) AS count,
               MIN(timestamp) AS start_time,
               MAX(timestamp) AS end_time
        FROM request_logs
        WHERE user_email = $1 AND timestamp > now() - interval '10 minutes'
        GROUP BY ip_address, apiname
        HAVING COUNT(*) > 20
        ORDER BY count DESC
        LIMIT 20
        "#,
    )
    .bind(email)
    .fetch_all(pool);

    let (api_vs_threats, success_rate, abusive_ips, abusive_patterns) = try_join!(
        api_vs_threats_fut,
        success_rate_fut,
        abusive_ips_fut,
        abusive_patterns_fut
    )?;

    Ok(AdvancedMonitorResponse {
        api_threat_heatmap: api_vs_threats,
        success_rate_data: success_rate,
        flagged_abuse: abusive_ips,
        rate_limit_alerts: abusive_patterns,
    })
}

pub async fn get_api_data(email: &str) -> Result<APIData, sqlx::Error> {
    let pool = get_global_pool();
    let api_rows: Vec<APIRow> = sqlx::query_as::<_, APIRow>(
        "SELECT apiname, endpoint_url, created_at, active_status
         FROM api 
         WHERE alert_email = $1 
         ORDER BY apiname",
    )
    .bind(email)
    .fetch_all(pool)
    .await?;

    let mut apis = Vec::new();

    for row in api_rows {
        let total_req: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM request_logs WHERE user_email = $1 AND apiname = $2",
        )
        .bind(email)
        .bind(&row.apiname)
        .fetch_one(pool)
        .await?;

        let last_used_opt: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT timestamp FROM request_logs 
             WHERE user_email = $1 AND apiname = $2 
             ORDER BY timestamp DESC LIMIT 1",
        )
        .bind(email)
        .bind(&row.apiname)
        .fetch_optional(pool)
        .await?;

        let last_used = last_used_opt
            .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "never".to_string());

        let threats: Vec<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT unnest(detected_threats) 
     FROM request_logs 
     WHERE user_email = $1 AND apiname = $2 and status = $3",
        )
        .bind(email)
        .bind(&row.apiname)
        .bind(false)
        .fetch_all(pool)
        .await?
        .into_iter()
        .flatten()
        .collect();

        apis.push(APIRecord {
            apiname: row.apiname,
            endpoint: row.endpoint_url,
            createdon: row.created_at,
            last_used,
            total_req,
            threats_blocked: threats,
            active_status: row.active_status,
        });
    }

    Ok(APIData { apis })
}

#[derive(Debug, serde::Serialize)]
pub struct MLResponse {
    pub status: String,
    pub threats_detected: Vec<String>,
    pub risk_score: i32,
}
