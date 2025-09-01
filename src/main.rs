#[macro_use]
extern crate rocket;

mod authorization;
mod db;
mod encryption;
mod models;

use crate::authorization::*;
use crate::encryption::*;
use crate::models::api::*;
use crate::models::api_alerts::*;
use crate::models::api_enc_data_key::*;
use crate::models::daily_usage::*;
use crate::models::request_logs::*;
use crate::models::user_verifications::get_verification_data;
use crate::models::user_verifications::make_user_verification;
use crate::models::users::*;
use base64::decode as base64_decode;
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use ipgeolocate::Locator;
use lettre::message::Message;
use lettre::transport::smtp::authentication::Credentials;
use lettre::SmtpTransport;
use lettre::Transport;
use once_cell::sync::Lazy;
use percent_encoding::percent_decode_str;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use rocket::form::Form;
use rocket::fs::FileServer;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::{Responder, Response};
use rocket::time::Duration;
use rocket::Request;
use rocket::{figment::Figment, Config};
use rocket::{serde::json::Json, State};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use rocket_dyn_templates::{context, Template};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashSet;
use std::ptr::null;
use std::{collections::HashMap, io::Cursor, sync::Mutex, time::Instant};
use uuid::Uuid;

static RATE_LIMITER: Lazy<Mutex<HashMap<String, (u32, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Serialize)]
struct ErrorResponse {
    msg: String,
}

#[derive(Debug)]
pub struct FirewallError {
    pub status: Status,
    pub msg: String,
}

impl FirewallError {
    pub fn new(status: Status, msg: &str) -> Self {
        Self {
            status,
            msg: msg.to_string(),
        }
    }
}

pub fn set_session(jar: &CookieJar<'_>, key: &str, value: &str) {
    let cookie = Cookie::new(key.to_string(), value.to_string());

    let mut cookie = cookie;
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::hours(12));
    cookie.set_same_site(SameSite::None);
    cookie.set_secure(true);
    jar.add(cookie);
}

pub fn set_small_session(jar: &CookieJar<'_>, key: &str, value: &str) -> bool {
    let cookie = Cookie::new(key.to_string(), value.to_string());

    let mut cookie = cookie;
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::minutes(5));
    cookie.set_same_site(SameSite::None);
    cookie.set_secure(true);
    jar.add(cookie);
    true
}

pub fn get_session(jar: &CookieJar<'_>, key: &str) -> Option<String> {
    jar.get(key).map(|cookie| cookie.value().to_string())
}

pub fn option_string_to_str(input: &Option<String>) -> &str {
    match input {
        Some(s) => s.as_str(),
        None => "",
    }
}

#[derive(Deserialize)]
struct LoginData {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupData {
    fullname: String,
    email: String,
    mypwd: String,
}

#[derive(Deserialize)]
struct Token {
    token: String,
}

#[derive(Deserialize)]
struct GoogleLogindata {
    email: String,
    #[serde(rename = "googleLogin")]
    google_login: bool,
}

#[derive(Deserialize)]
struct API {
    apiname: String,
    apidesc: String,
    endpoint_url: String,
    auth_type: String,
    allowed_ip: String,
    rate_limit: String,
    threat_filters: String,
}
#[derive(Deserialize)]
struct ActiveUser {
    key: String,
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

#[derive(Deserialize, Debug)]
pub struct APIDisable {
    pub apiname: String,
}

#[post("/validate_active_user", data = "<payload>")]
async fn validate_active_user(
    payload: Json<ActiveUser>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, &payload.key);
    let currentuser: &str = option_string_to_str(&cuser);
    println!("Active user -> {}", currentuser);
    if currentuser.is_empty() {
        return Json(
            json!({"status": false, "message": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    return Json(json!({"status": true, "message": "Active user session found."}));
}

#[derive(Deserialize)]
struct CUser {
    key: String,
}

#[post("/getcurrentuserinfo", data = "<payload>")]
async fn get_active_user_info(
    payload: Json<CUser>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, &payload.key);
    let currentuser: &str = option_string_to_str(&cuser);
    //println!("Active user -> {}",currentuser);
    if currentuser.is_empty() {
        return Json(
            json!({"status": false, "message": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match retrieve_current_user_info(currentuser).await {
        Ok(udata) => {
            let data: Vec<String> = vec![
                udata.fullname.clone(),
                udata.email.clone(),
                udata.registered_on.to_string(),
            ];
            return Json(json!({
                "status": true,
                "message": "User Data fetched Successfully.",
                "fullname": udata.fullname,
                "email": udata.email,
            }));
        }
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return Json(json!({
                "status": false,
                "message": "Failed to fetch user data",
                "redirectTO": "/action"
            }));
        }
    }
}

#[post("/login", data = "<payload>")]
async fn login_handler(
    payload: Json<LoginData>,
    pool: &State<PgPool>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    match retreive_pwd(&payload.username).await {
        Ok(mypwd) => {
            if verify_password(&mypwd, &payload.password) {
                set_session(jar, "current_user", &payload.username);

                match update_loggedin_status(&payload.username).await {
                    Ok(true) => Json(json!({"status": true})),
                    Ok(false) => {
                        Json(json!({"status": false, "message": "Could not update login status"}))
                    }
                    Err(e) => Json(json!({"status": false, "message": format!("DB error: {}", e)})),
                }
            } else {
                Json(json!({"status": false, "message": "Password mismatch"}))
            }
        }
        Err(_) => Json(json!({"status": false, "message": "User not found"})),
    }
}

#[post("/google_login", data = "<payload>")]
async fn google_auth_login(
    payload: Json<GoogleLogindata>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    match google_login(&payload.email).await {
        Ok(_) => match update_loggedin_status(&payload.email).await {
            Ok(true) => {
                set_session(jar, "current_user", &payload.email);
                Json(json!({ "status": true, "message": "Login successful" }))
            }
            Ok(false) => {
                Json(json!({ "status": false, "message": "Could not update login status" }))
            }
            Err(e) => Json(json!({ "status": false, "message": format!("DB error: {}", e) })),
        },
        Err(_) => Json(json!({ "status": false, "message": "Login failed." })),
    }
}

#[post("/registration", data = "<payload>")]
async fn register_handler(payload: Json<SignupData>) -> Json<serde_json::Value> {
    let pwd = hash_password(&payload.mypwd);
    let ustatus = false;
    let token = Uuid::new_v4().to_string();
    let subject: String = "Ethixion - Verify Your Email to Activate Your Account".to_string();

    let body = format!(
    "Hello Ethixior,

Thank you for signing up with Ethixion.

To complete your account setup and enable all security & alert services, please verify your email address by clicking the link below:

👉 Verify My Email: {}

This verification step is mandatory to ensure secure access and uninterrupted Ethixion services.

If you did not request this account, you can safely ignore this email.

Best regards,
Ethixion Security Team
Secure. Reliable. Alert.
",format!("http://127.0.0.1:3000/verify_user?token={}",token) 
);
    match insert_user(&payload.fullname, &payload.email, &pwd, &ustatus).await {
        Ok(_) => {
            let _ = make_user_verification(&payload.email, &token).await;
            send_alert_email(&payload.email, &subject, &body).await;
            Json(
                json!({ "status": "success", "msg": "Kindly activate you account by clicking on the link sent on your email." }),
            )
        }
        Err(_) => Json(
            json!({ "status": "error", "msg": "Registration failed or email already exists." }),
        ),
    }
}

#[get("/verify_account?<token>")]
async fn verify_account(token: String) -> Json<serde_json::Value> {
    let datetime = chrono::Utc::now().naive_utc();
    let subject = "Welcome to Ethixion - Your Account is Ready!".to_string();

    let body = format!(
        "Hello Dear Ethixior,\n\nWelcome to Ethixion! 🎉  \nYour account has been successfully created and activated.\n\n\
        You can now access all our advanced security and alert services...\n\n\
        👉 Login to Your Account: {}\n\n\
        Best regards,\nEthixion Security Team",
        "http://127.0.0.1:3000/action"
    );

    let data = match get_verification_data(&token).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Json(json!({
                "status": "expired",
                "msg": "Link has expired. Please register again."
            }));
        }
        Err(_) => {
            return Json(json!({
                "status": "failed",
                "msg": "Server error. Please try again later."
            }));
        }
    };

    match update_verified_status(&data.email).await {
        Ok(_) => {
            send_alert_email(&data.email, &subject, &body).await;
            Json(json!({
                "status": "success",
                "msg": "Account verified successfully."
            }))
        }
        Err(_) => Json(json!({
            "status": "failed",
            "msg": "Server error. Please try again later."
        })),
    }
}

#[post("/api", data = "<payload>")]
async fn api_handler(payload: Json<API>, jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "message": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    } else {
        println!("Active User: {}", user);
    }
    println!("Cookies in jar:");
    for cookie in jar.iter() {
        println!("{} = {}", cookie.name(), cookie.value());
    }
    let prefix = "ethix";
    let random_part: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32 - prefix.len())
        .map(char::from)
        .collect();
    let apikey = format!("{}{}", prefix, random_part);
    let enc_apikey: String = hash_password(&apikey);
    match insert_api(
        &payload.apiname,
        &enc_apikey,
        &payload.apidesc,
        &payload.endpoint_url,
        &payload.auth_type,
        &payload.allowed_ip,
        &payload.rate_limit,
        &payload.threat_filters,
        &user,
    )
    .await
    {
        Ok(_) => {
            let aes_key = &generate_aes256_key();
            let _ = make_api_enc_key_call(&payload.apiname, &user, &aes_key).await;
            Json(
                json!({"status": "done", "message": "API Created Successfully.", "apiname": &payload.apiname, "apikey": apikey}),
            )
        }
        Err(e) => {
            eprintln!("Error occurred: {:?}", e);
            Json(json!({
                "status": "error",
                "message": format!("Error Occured: {}", e)
            }))
        }
    }
}

#[derive(Deserialize)]
struct EthixRules {
    apiname: String,
    threat_filters: String,
}

#[post("/setethixrules", data = "<payload>")]
async fn set_ethix_rules(
    payload: Json<EthixRules>,
    pool: &State<PgPool>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    } else {
        println!("Active User: {}", user);
    }
    println!("Cookies in jar:");
    for cookie in jar.iter() {
        println!("{} = {}", cookie.name(), cookie.value());
    }
    let mut set = HashSet::new();
    if let Ok(Some(myfilters)) = retrieve_apifilters(&user).await {
        set.insert(myfilters.threat_filters.unwrap());
    }
    set.insert(payload.threat_filters.clone());
    let filters: Vec<String> = set.into_iter().collect();
    let filters_str = filters.join(",");
    let email = retrieve_email_from_api(&payload.apiname).await.unwrap();
    let subject: String = "Ethixion Firewall - Your API Threat Filters Were Updated".to_string();
    let body = format!(
    "Hello Dear Ethixior,

This is to inform you that the threat filter settings for your API \"{}\" were updated successfully on {}.

If you made this change, no further action is needed.

However, if you did NOT authorize this change, your account may be compromised. We strongly recommend that you:

1. Change your Ethixion account password immediately.
2. Review your recent activity and API configuration.
3. Contact support if you notice anything suspicious.

Your account security is our top priority.
This is an automated message. Do not reply to this email.

Stay protected,  
Ethixion Security Team
",
    payload.apiname,
    Local::now().format("%Y-%m-%d %H:%M:%S")
);
    match update_api_filters(&payload.apiname, &filters_str).await {
        Ok(_) => {
            send_alert_email(&email, &subject, &body).await;
            Json(json!({"status": true, "msg": "Filters Applied to api successfully."}))
        }
        Err(e) => Json(json!({"status": false, "msg": format!("Error -> {e}")})),
    }
}

#[post("/get_todays_threat_logs")]
async fn get_todays_threat_logs(
    pool: &State<PgPool>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    } else {
        println!("Active User: {}", user);
    }
    match retrieve_request_logs(user).await {
        Ok(logs_data) => {
            if logs_data.is_empty() {
                Json(
                    json!({"status": false, "msg": "No threat logs found for today requests. or You havent made any request today."}),
                )
            } else {
                Json(json!({"status": true, "logs": logs_data }))
            }
        }

        Err(e) => Json(
            json!({"status": false, "msg": format!("Something went wrong while fetching logs data. {e}")}),
        ),
    }
}

#[post("/dashboard_data")]
async fn get_todays_dashboard_data(
    pool: &State<PgPool>,
    jar: &CookieJar<'_>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    } else {
        println!("Active User: {}", user);
    }
    match get_dashboard_data(user).await {
        Ok(data) => Json(json!({"status": "success", "ReqData": data})),
        Err(err) => Json(
            json!({"status": "failed", "msg": format!("Error got while processing your request -> {}", err)}),
        ),
    }
}

#[post("/reportlogs")]
async fn get_report_logs(pool: &State<PgPool>, jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);

    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(json!({
            "status": "NoActiveUserError",
            "msg": "No Active user session found. Kindly login again!",
            "redirectTO": "/action"
        }));
    }

    let match1 = get_overall_report_logs(user).await;
    let match2 = get_todays_stats(user).await;

    match (match2, match1) {
        (Ok(data1), Ok(data2)) => {
            //println!("Data1 (Today's stats) => {:?}", data1);
            //println!("Data2 (Overall logs) => {:?}", data2);

            Json(json!({
                "status": "success",
                "data1": data1,
                "data2": data2,
            }))
        }
        (Err(e), _) | (_, Err(e)) => {
            println!("Error fetching logs for report by gt => {}", e);
            Json(json!({
                "status": "failed",
                "msg": format!("Error => {}", e)
            }))
        }
    }
}

#[post("/security_details")]
async fn get_dashboard_security_details(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match get_security_dashboard(user).await {
        Ok(dt) => Json(json!({ "status": "success", "securitydata": dt })),
        Err(e) => {
            println!("❌ Error fetching security dashboard: {e}");
            Json(json!({ "status": "failed", "msg": format!("Error => {e}") }))
        }
    }
}

#[post("/trends_details")]
async fn get_dashboard_trend_details(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match get_system_trend_monitor(user).await {
        Ok(dt) => {
            //println!("Inside OK arm of match.");
            //println!("TrendDashboardResponse => {:?}", dt);
            Json(json!({ "status": "success", "trenddata": dt }))
        }
        Err(e) => {
            //println!("Error fetching security dashboard: {e}");
            Json(json!({ "status": "failed", "msg": format!("Error => {e}") }))
        }
    }
}

#[post("/trends_status")]
async fn get_dashboard_trends_status(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match get_status_trend_monitor(user).await {
        Ok(trend_status) => {
            //println!("Trend status fetched successfully: {:?}", trend_status);
            Json(json!({ "status": "success", "trends_status": trend_status }))
        }
        Err(e) => {
            println!("Error => {e}");
            Json(json!({ "status": "failed", "msg": format!("Error => {e}") }))
        }
    }
}

#[post("/advance_monitors")]
async fn get_dashboard_adavnce_monitorings(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match get_advanced_monitors(user).await {
        Ok(adv_monitors) => {
            println!("Advance Montiors: {:?}", adv_monitors);
            Json(json!({ "status": "success", "adv_monitors": adv_monitors }))
        }
        Err(e) => {
            println!("Error: {e}");
            Json(json!({"status": "failed", "msg": format!("Error: {e}")}))
        }
    }
}

#[post("/api_overview")]
async fn get_api_overview(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match get_api_data(user).await {
        Ok(apidata) => {
            println!("\nAPI Data: {:?}", apidata);
            Json(json!({"status": "success", "apidata": apidata}))
        }
        Err(e) => {
            println!("Error: {e}");
            Json(json!({"status": "failed", "msg": format!("Error: {e}")}))
        }
    }
}

#[post("/disable_API", data = "<payload>")]
async fn disable_api_req(
    jar: &CookieJar<'_>,
    payload: Json<APIDisable>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match disable_api(&payload.apiname).await {
        Ok(status) => {
            let subject: String = "Ethixion Firewall - API Key Disabled".to_string();
            let body = format!(
    "Hello Ethixor,

We want to inform you that the API Key for your API \"{}\" was disabled on {}.

If you performed this action, no further steps are required.  
However, if you did not authorize this change, your account may be compromised. For your security, we strongly recommend that you:

1. Change your Ethixion account password immediately.  
2. Review your recent activity and API configurations.  
3. Contact our support team if you notice anything unusual.

Your security is our top priority.  

This is an automated message. Please do not reply to this email.

Stay secure,  
Ethixion Security Team
",
    &payload.apiname,
    Local::now().format("%Y-%m-%d %H:%M:%S")
);
            send_alert_email(&user, &subject, &body).await;
            Json(
                json!({ "status": status, "msg": format!("{} API Disabled Successfully", payload.apiname) }),
            )
        }
        Err(e) => Json(
            json!({ "status": false, "msg": format!("{} API Disable failed. Error => {e}", payload.apiname) }),
        ),
    }
}

#[post("/enable_API", data = "<payload>")]
async fn enable_api_req(jar: &CookieJar<'_>, payload: Json<APIDisable>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match enable_api(&payload.apiname).await {
        Ok(status) => {
            let subject: String = "Ethixion Firewall - API Enabled".to_string();
            let body = format!(
    "Hello Ethixor,

We want to inform you that your API \"{}\" was enabled on {}.

If you performed this action, no further steps are required.  
However, if you did **not** authorize this change, your account may be compromised. For your security, we strongly recommend that you:

1. Change your Ethixion account password immediately.  
2. Review your recent activity and API configurations.  
3. Contact our support team if you notice anything unusual.

Your security is our top priority.  

This is an automated message. Please do not reply to this email.

Stay secure,  
Ethixion Security Team
",
    payload.apiname,
    Local::now().format("%Y-%m-%d %H:%M:%S")
);
            send_alert_email(&user, &subject, &body).await;
            Json(
                json!({ "status": status, "msg": format!("{} API Enabled Successfully", payload.apiname) }),
            )
        }
        Err(e) => Json(
            json!({ "status": false, "msg": format!("{} API Enable failed. Error => {e}", payload.apiname) }),
        ),
    }
}

#[post("/delete_API", data = "<payload>")]
async fn delete_api_req(jar: &CookieJar<'_>, payload: Json<APIDisable>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match delete_api(&payload.apiname).await {
        Ok(status) => {
            let subject: String = "Ethixion Firewall - API Deletion Detected".to_string();
            let body = format!(
    "Hello Ethixor,

We want to inform you that your API \"{}\" was deleted on {}.

If you performed this action, no further steps are required.  
However, if you did not authorize this deletion, your account may be compromised. For your security, we strongly recommend that you:

1. Change your Ethixion account password immediately.  
2. Review your recent activity and API configurations.  
3. Contact our support team if you notice anything suspicious.

Protecting your APIs and account is our highest priority.  

This is an automated message. Please do not reply to this email.

Stay secure,  
Ethixion Security Team
",
    &payload.apiname,
    Local::now().format("%Y-%m-%d %H:%M:%S")
);
            send_alert_email(&user, &subject, &body).await;

            Json(
                json!({ "status": status, "msg": format!("{} API Deleted Successfully", payload.apiname) }),
            )
        }
        Err(e) => Json(
            json!({ "status": false, "msg": format!("{} API Deletion failed. Error => {e}", payload.apiname) }),
        ),
    }
}

#[post("/regenerate_api_key", data = "<payload>")]
async fn regenerate_api_key(
    jar: &CookieJar<'_>,
    payload: Json<APIDisable>,
) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    let prefix = "ethix";
    let random_part: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32 - prefix.len())
        .map(char::from)
        .collect();
    let apikey = format!("{}{}", prefix, random_part);
    println!("API Key is => {apikey}");
    let enc_apikey: String = hash_password(&apikey);
    match regenerate_api_key_req(&payload.apiname, &enc_apikey).await {
        Ok(status) => {
            let subject: String = "Ethixion Firewall - API Key Regenerated".to_string();
            let body = format!(
    "Hello Ethixor,

We want to inform you that the API Key for your API \"{}\" was regenerated on {}.

If you performed this action, no further steps are required.  
However, if you did not authorize this change, your account may be compromised. For your security, we strongly recommend that you:

1. Change your Ethixion account password immediately.  
2. Review your recent activity and API configurations.  
3. Contact our support team if you notice anything unusual.

Your security is our top priority.  

This is an automated message. Please do not reply to this email.

Stay secure,  
Ethixion Security Team
",
    &payload.apiname,
    Local::now().format("%Y-%m-%d %H:%M:%S")
);
            send_alert_email(&user, &subject, &body).await;

            Json(
                json!({"status": "success", "msg": "API Key regenerated successfully.", "apiname": &payload.apiname,"apikey": &apikey}),
            )
        }
        Err(e) => {
            eprintln!("Error => {e}");
            Json(json!({"status": "failed", "msg": format!("API key regneration failed")}))
        }
    }
}

#[post("/retrieve_api_alerts")]
async fn retrieve_api_alerts_handler(jar: &CookieJar<'_>) -> Json<serde_json::Value> {
    let cuser = get_session(jar, "current_user");
    let user: &str = option_string_to_str(&cuser);
    if user.is_empty() {
        println!("No session token found. Please login.");
        return Json(
            json!({"status": "NoActiveUserError", "msg": "No Active user session found. Kindly login again!", "redirectTO": "/action"}),
        );
    }
    match retrieve_api_alerts(&user).await {
        Ok(data) => {
            println!("API Alert Data => {:?}", data);
            Json(json!({ "status": "success", "api_alerts_data": data }))
        }
        Err(e) => {
            println!("Error => {e}");
            Json(json!({ "status": "failed", "msg": "Something went wrong with the server." }))
        }
    }
}

// Ethixion Request Scanning Handler Funcs --------------------------------------------------------------------->

const SAFE_IPS: &[&str] = &["127.0.0.1", "::1", "192.168.0.1"];

async fn check_any_ip_allowed(
    user_ip: &str,
    safe_ips: &[&str],
    allowed_countries: &[&str],
) -> bool {
    // Allow loopback and explicitly safe IPs
    if user_ip == "127.0.0.1" || user_ip == "::1" || safe_ips.contains(&user_ip) {
        return true;
    }

    // Geolocation check for user's IP
    if is_ip_allowed(user_ip, allowed_countries).await {
        return true;
    }

    // Also geolocate each safe IP as fallback (optional)
    for &ip in safe_ips {
        if is_ip_allowed(ip, allowed_countries).await {
            return true;
        }
    }

    false
}

pub struct APIRequestInfo {
    pub headers: APIURLHeaders,
    pub raw_headers: Vec<(String, String)>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for APIRequestInfo {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = req.headers();
        let total_headers = headers.len();

        let raw_headers: Vec<(String, String)> = headers
            .iter()
            .map(|h| (h.name().to_string(), h.value().to_string()))
            .collect();

        let api_headers = APIURLHeaders {
            apiname: headers
                .get_one("x-app-name")
                .unwrap_or_default()
                .to_string(),
            apikey: headers.get_one("x-api-key").unwrap_or_default().to_string(),
            client_ip: req
                .client_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".into()),
            method: req.method().as_str().to_string(),
            uri: req.uri().to_string(),
            user_agent: headers
                .get_one("User-Agent")
                .unwrap_or_default()
                .to_string(),
            host: headers.get_one("Host").unwrap_or_default().to_string(),
            referer: headers.get_one("Referer").map(|s| s.to_string()),
            content_type: headers.get_one("Content-Type").map(|s| s.to_string()),
            content_length: headers
                .get_one("Content-Length")
                .and_then(|c| c.parse().ok()),
            total_headers,
            suspicious: false,
            matched_pattern: None,
            redirect_url: headers
                .get_one("x-redirect-url")
                .unwrap_or_default()
                .to_string(),
            origin_url: headers
                .get_one("x-origin-url")
                .unwrap_or_default()
                .to_string(),
        };

        Outcome::Success(APIRequestInfo {
            headers: api_headers,
            raw_headers,
        })
    }
}

impl<'r> Responder<'r, 'static> for FirewallError {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let body_str = serde_json::to_string(&ErrorResponse { msg: self.msg }).unwrap();
        let body_size = body_str.len();

        Response::build()
            .status(self.status)
            .header(rocket::http::Header::new(
                "Content-Type",
                "application/json",
            ))
            .sized_body(body_size, Cursor::new(body_str))
            .ok()
    }
}

pub async fn send_alert_email(recipient: &str, subject: &str, body: &str) {
    let recipient = recipient.to_string();
    let subject = subject.to_string();
    let body = body.to_string();

    tokio::task::spawn_blocking(move || {
        let email = match Message::builder()
            .from(
                "Ethixion Firewall Alert <mypyschbuddy@gmail.com>"
                    .parse()
                    .unwrap(),
            )
            .to(recipient.parse().unwrap())
            .subject(subject)
            .body(body.clone())
        {
            Ok(email) => email,
            Err(e) => {
                eprintln!("[Email Error] Failed to build message: {}", e);
                return;
            }
        };

        let creds = Credentials::new(
            "mypyschbuddy@gmail.com".to_string(),
            "ujdbdhgxpizjmghj".to_string(),
        );

        let mailer = match SmtpTransport::relay("smtp.gmail.com") {
            Ok(builder) => builder.credentials(creds).build(),
            Err(e) => {
                eprintln!("[Email Error] SMTP transport setup failed: {}", e);
                return;
            }
        };

        match mailer.send(&email) {
            Ok(_) => println!("[Email Sent] Alert sent to {}", recipient),
            Err(e) => eprintln!("[Email Error] Failed to send email: {}", e),
        };
    })
    .await
    .ok();
}

async fn is_ip_allowed(ip: &str, allowed_countries: &[&str]) -> bool {
    // Allow localhost IPs explicitly (both IPv4 and IPv6)
    if ip == "127.0.0.1" || ip == "::1" {
        return true;
    }

    let ip_owned = ip.to_string();

    match tokio::task::spawn_blocking(move || Locator::get(&ip_owned, "")).await {
        Ok(Ok(geo)) => {
            // Check if the country is in allowed list
            allowed_countries.contains(&geo.country.as_str())
        }
        _ => false, // If lookup fails, deny by default
    }
}

pub struct ExtractOrigin(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ExtractOrigin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let origin = request.headers().get_one("Origin").map(String::from);
        Outcome::Success(ExtractOrigin(origin))
    }
}

/*#[post("/ethix_auth", data = "<payload>")]
pub async fn ethix_auth(payload: Form<APIForm>, req: &Request<'_>) -> Template {
    let apidata = payload.into_inner();

    let origin_url = apidata
        .origin_url
        .clone()
        .unwrap_or_else(|| "http://ethicaldude.website3.me".to_string());

    let request_body = apidata.body.clone().unwrap_or_default();

    let mut request_data = HttpRequestData {
        apiname: apidata.apiname.clone(),
        apikey: apidata.apikey.clone(),
        client_ip: req.client_ip().map(|ip| ip.to_string()).unwrap_or_default(),
        method: req.method().as_str().to_string(),
        uri: req.uri().to_string(),
        user_agent: req
            .headers()
            .get_one("User-Agent")
            .unwrap_or("")
            .to_string(),
        host: req.headers().get_one("Host").unwrap_or("").to_string(),
        referer: req.headers().get_one("Referer").map(|s| s.to_string()),
        content_type: req.content_type().map(|ct| ct.to_string()),
        content_length: req
            .headers()
            .get_one("Content-Length")
            .and_then(|cl| cl.parse().ok()),
        total_headers: req.headers().len(),
        suspicious: false,
        matched_pattern: None,
        redirect_url: apidata.target_url.clone(),
        origin_url: origin_url.clone(),
        body: request_body,
    };

    // ✅ Call new gatekeeper for both headers & body
    let gatekeeper_result = ethix_gatekeeperII(&mut request_data).await;

    // ✅ Same page, no matter which gatekeeper is used
    Template::render(
        "ethixionPage",
        context! {
            status: gatekeeper_result.status,
            redirect_url: gatekeeper_result.redirect_url,
            origin_url: gatekeeper_result.origin_url,
            logs: gatekeeper_result.logs,
        },
    )
}*/

#[derive(Serialize)]
struct GatekeeperResponse {
    status: bool,
    redirect_url: String,
    origin_url: String,
    logs: Vec<String>,
}

pub fn generate_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub async fn validate_headers(
    request_info: &APIRequestInfo,
    req_id: &str,
    admin_email: &str,
    logs: &mut Vec<String>,
    fallbacklogs: &mut Vec<String>,
    detected_threats: &mut Vec<String>,
    alert_type: &mut Vec<String>,
    severity_vec: &mut Vec<String>,
    msg_vec: &mut Vec<String>,
) -> Option<Json<GatekeeperResponse>> {
    let max_total_header_size: usize = 8192;
    let max_header_count: usize = 100;

    let mut total_size = 0;
    for (name, value) in request_info.raw_headers.iter() {
        total_size += name.len() + value.len() + 4;
    }

    if total_size > max_total_header_size {
        logs.push(format!(
            "[✘] Total header size exceeded ({} > {} bytes)",
            total_size, max_total_header_size
        ));
        println!("[✘] Total header size exceeded {total_size} > {max_total_header_size} bytes");
        fallbacklogs.push("Total request headers size too large".to_string());
        detected_threats.push("Total Header Size Exceeded".to_string());
        alert_type.push("Header Size Violation".to_string());
        severity_vec.push("high".to_string());
        msg_vec.push("Combined HTTP headers exceeded safe processing limit.".to_string());

        let _ = make_request_log(
            req_id,
            admin_email,
            &request_info.headers.apiname,
            &request_info.headers.origin_url,
            "",
            false,
            fallbacklogs.clone(),
            &request_info.headers.client_ip,
            &request_info.headers.user_agent,
            &detected_threats,
        )
        .await;

        let _ = insert_api_alert(
            admin_email,
            &request_info.headers.apiname,
            req_id,
            &alert_type,
            &severity_vec,
            &msg_vec,
            "pending",
        )
        .await;

        return Some(Json(GatekeeperResponse {
            status: false,
            redirect_url: "".to_string(),
            origin_url: request_info.headers.origin_url.clone(),
            logs: logs.clone(),
        }));
    }

    // Check header count
    if request_info.raw_headers.len() > max_header_count {
        logs.push(format!(
            "[✘] Too many headers sent in request ({} > {} allowed)",
            request_info.raw_headers.len(),
            max_header_count
        ));
        fallbacklogs.push("Too many headers in request".to_string());
        detected_threats.push("Excessive Header Count".to_string());
        alert_type.push("Header Flood".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("Request exceeded maximum allowed number of headers.".to_string());

        let _ = make_request_log(
            req_id,
            admin_email,
            &request_info.headers.apiname,
            &request_info.headers.origin_url,
            "",
            false,
            fallbacklogs.clone(),
            &request_info.headers.client_ip,
            &request_info.headers.user_agent,
            &detected_threats,
        )
        .await;

        let _ = insert_api_alert(
            admin_email,
            &request_info.headers.apiname,
            req_id,
            &alert_type,
            &severity_vec,
            &msg_vec,
            "pending",
        )
        .await;

        return Some(Json(GatekeeperResponse {
            status: false,
            redirect_url: "".to_string(),
            origin_url: request_info.headers.origin_url.clone(),
            logs: logs.clone(),
        }));
    }

    None
}

#[post("/ethix_gatekeeper")]
async fn ethix_gatekeeper_handler(
    request_info: APIRequestInfo,
    pool: &State<PgPool>,
) -> Json<GatekeeperResponse> {
    let req_id = generate_request_id();
    let mut fallbacklogs: Vec<String> = Vec::new();
    let mut detected_threats: Vec<String> = Vec::new();
    let mut blocked: bool = false;
    let headers = &request_info.headers;
    let mut logs = Vec::new();
    let mut alert_status: bool = false;
    let mut alert_type = Vec::new();
    let mut severityVec = Vec::new();
    let mut msgVec = Vec::new();

    let admin_email = match retrieve_email_from_api(&headers.apiname).await {
        Ok(email) => email,
        Err(_) => "admin@example.com".to_string(),
    };

    println!("Processing request: {}", req_id);

    logs.push("[***] Starting Ethixion security checks".to_string());
    println!("[***] Ethixion security checks has started...");

    //step 0: Headers Validation(size check with duplicate headers checking.)
    if let Some(response) = validate_headers(
        &request_info,
        &req_id,
        &admin_email,
        &mut logs,
        &mut fallbacklogs,
        &mut detected_threats,
        &mut alert_type,
        &mut severityVec,
        &mut msgVec,
    )
    .await
    {
        return response;
    }

    // Step 1: Retrieve stored API key
    let stored_key: Option<String> = match retrieve_apikey(&headers.apiname).await {
        Ok(k) => {
            println!("[✔] API key retrieved successfully");
            Some(k)
        }
        Err(_) => {
            logs.push("[✘] Invalid credentials entered (API name not found)".to_string());
            fallbacklogs.push("Invalid credentials entered (API name not found)".to_string());
            alert_type.push("Invalid API Access".to_string());
            severityVec.push("medium".to_string());
            msgVec.push("Request attempted on a non-existent or invalid API.".to_string());
            blocked = true;

            let _ = make_request_log(
                &req_id,
                &admin_email,
                &headers.apiname,
                &headers.origin_url,
                "",
                false,
                fallbacklogs.clone(),
                &headers.client_ip,
                &headers.user_agent,
                &detected_threats,
            )
            .await;

            let _ = insert_api_alert(
                &admin_email,
                &headers.apiname,
                &req_id,
                &alert_type,
                &severityVec,
                &msgVec,
                "pending",
            )
            .await;

            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
    };

    let stored_key = match stored_key {
        Some(key) if !key.is_empty() => key,
        _ => {
            fallbacklogs.push("Empty API key found in system.".to_string());

            let _ = make_request_log(
                &req_id,
                &admin_email,
                &headers.apiname,
                &headers.origin_url,
                "",
                false,
                fallbacklogs.clone(),
                &headers.client_ip,
                &headers.user_agent,
                &detected_threats,
            )
            .await;

            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
    };

    // Step 2: Verify provided key against stored key
    if !verify_password(&stored_key, &headers.apikey) {
        logs.push("[✘] API key verification failed due to invalid api key entered.".to_string());
        fallbacklogs.push("API key verification failed".to_string());
        detected_threats.push("API key mismatch".to_string());
        alert_type.push("API Key Mismatch".to_string());
        severityVec.push("high".to_string());
        msgVec.push("API key provided did not match stored key.".to_string());
        blocked = true;
        let _ = make_request_log(
            &req_id,
            &admin_email,
            &headers.apiname,
            &headers.origin_url,
            "",
            false,
            fallbacklogs.clone(),
            &headers.client_ip,
            &headers.user_agent,
            &detected_threats,
        )
        .await;
        let _ = insert_api_alert(
            &admin_email,
            &headers.apiname,
            &req_id,
            &alert_type,
            &severityVec,
            &msgVec,
            "pending",
        )
        .await;
        return Json(GatekeeperResponse {
            status: false,
            redirect_url: "".to_string(),
            origin_url: headers.origin_url.clone(),
            logs,
        });
    } else {
        logs.push("[✔] API key verification passed".to_string());
    }

    let ip = &headers.client_ip;

    // Step 2.1: Checking API active_status
    match retrieve_api_isactive(&headers.apiname).await {
        Ok(true) => {
            println!("[✔] Service for current API is Enabled.");
        }
        Ok(false) => {
            blocked = true;
            logs.push("[✘] Service for current API is Disabled.".to_string());
            fallbacklogs.push("Service for current API is Disabled.".to_string());
            alert_type.push("Disabled API Access".to_string());
            severityVec.push("medium".to_string());
            msgVec.push("Request attempted on a disabled API.".to_string());
            println!("[✘] Service for current API is Disabled.");
            let subject: String =
                "Ethixion Firewall - Request Detected on Disabled API".to_string();
            let body = format!(
                "Hello Dear Ethixior,

Our system detected a request made to your API \"{}\" on {}.  
This request was **declined by Ethixion Gatekeeper** because the API is currently *disabled*.

To resume using this API, you will need to log in to your Ethixion Dashboard and enable it.  
Only after re-enabling the API will requests be processed successfully.

If you intentionally disabled this API, no further action is required.  
If you did not disable it and are seeing this message unexpectedly, we recommend that you:

1. Log in to your Ethixion account and verify your API settings.
2. Review your recent activity for any suspicious changes.
3. Contact our support team if you suspect unauthorized access.

Your account security and service reliability remain our highest priority.  
This is an automated message. Please do not reply directly to this email.

Stay secure,  
Ethixion Security Team
",
                &headers.apiname,
                Local::now().format("%Y-%m-%d %H:%M:%S")
            );

            send_alert_email(&admin_email, &subject, &body).await;
            let _ = make_request_log(
                &req_id,
                &admin_email,
                &headers.apiname,
                &headers.origin_url,
                "",
                false,
                fallbacklogs.clone(),
                ip,
                &headers.user_agent,
                &detected_threats,
            )
            .await;
            let _ = insert_api_alert(
                &admin_email,
                &headers.apiname,
                &req_id,
                &alert_type,
                &severityVec,
                &msgVec,
                "pending",
            )
            .await;

            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
        Err(e) => {
            blocked = true;
            //println!("[✘] Failed to check API active_status: {:?}", e);
            fallbacklogs.push("Error checking API active_status".to_string());

            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
    }

    //step 2.2: check daily quota limit
    match map_api_daily_usage(&admin_email, &headers.apiname).await {
        Ok(_) => {
            println!("Daily usage is allowed.");
        }
        Err(e) => {
            blocked = true;
            logs.push(
                "[✘] Daily request limit (500) reached for your Ethixion API usage.".to_string(),
            );
            fallbacklogs
                .push("Daily request limit (500) reached for your Ethixion API usage.".to_string());
            alert_type.push("Daily Usage Limit Reached".to_string());
            severityVec.push("high".to_string());
            msgVec.push("User exceeded the daily API request quota of 500.".to_string());
            println!("Daily usage quota limit reached. Please try after 12:00 AM.");
            let _ = make_request_log(
                &req_id,
                &admin_email,
                &headers.apiname,
                &headers.origin_url,
                "",
                false,
                fallbacklogs.clone(),
                ip,
                &headers.user_agent,
                &detected_threats,
            )
            .await;
            let _ = insert_api_alert(
                &admin_email,
                &headers.apiname,
                &req_id,
                &alert_type,
                &severityVec,
                &msgVec,
                "pending",
            )
            .await;
            let subject: String = "Ethixion Firewall - Daily API Request Limit Reached".to_string();
            let body = format!( "Hello Dear Ethixior, Our system detected that your API \"{}\" has reached its daily request limit of 500(free plan) requests on {}. As a result, further requests made today will be automatically blocked by the Ethixion Gatekeeper. Your request count will reset at 12:00 AM (server time), after which requests will be accepted again. If you need higher request capacity, you can: 1. Log in to your Ethixion Dashboard to review your current usage. 2. Upgrade your plan or request a quota increase. 3. Contact our support team for further assistance. Your security and uninterrupted service remain our top priority. This is an automated message. Please do not reply directly to this email. Stay secure, Ethixion Security Team ", &headers.apiname, Local::now().format("%Y-%m-%d %H:%M:%S") );
            send_alert_email(&admin_email, &subject, &body).await;

            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
    }

    // Step 3: Retrieve filters
    let filters = match retrieve_predefined_filters(&headers.apiname).await {
        Ok(Some(f)) => {
            println!("[✔] Filter rules loaded");
            f
        }
        _ => {
            //println!("[✘] Could not load filter rules");
            fallbacklogs.push("Could not load filter rules".to_string());
            blocked = true;
            return Json(GatekeeperResponse {
                status: false,
                redirect_url: "".to_string(),
                origin_url: headers.origin_url.clone(),
                logs,
            });
        }
    };

    // Step 4: Suspicious Header Check
    if headers.host.is_empty() || headers.host.len() > 256 {
        logs.push("[☠︎︎] First malicious request detected - ".to_string());
        fallbacklogs.push("Invalid or missing Host header.".to_string());
        detected_threats.push("Missing/Invalid Host Header".to_string());
        alert_type.push("Missing/Invalid Host Header".to_string());
        severityVec.push("medium".to_string());
        msgVec.push("The request contains a missing or invalid Host header, which may indicate a host header attack or misconfigured client.".to_string());

        blocked = true;
        alert_status = true;
    }
    if let Some(ref referer) = headers.referer {
        if referer.contains("127.") || referer.contains("localhost") {
            logs.push("[☠︎︎] Second malicious request detected. ".to_string());
            fallbacklogs.push("Suspicious referer header.".to_string());
            detected_threats.push("Localhost Referer".to_string());
            alert_type.push("Suspicious Referer Header".to_string());
            severityVec.push("medium".to_string());
            msgVec
                .push("Referer header points to localhost; possible header tampering.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 5: IP Allowlist
    if let Some(ref allowed_ip_str) = filters.allowed_ip {
        let allowed_ips: Vec<&str> = allowed_ip_str.split(',').map(|s| s.trim()).collect();
        if !allowed_ips.contains(&ip.as_str()) && !SAFE_IPS.contains(&ip.as_str()) {
            logs.push("[☠︎︎] Third malicious request detected. ".to_string());
            fallbacklogs.push(format!("IP {} not in allowlist", ip));
            detected_threats.push("IP Not in Allowlist".to_string());
            alert_type.push("IP Not in Allowlist".to_string());
            severityVec.push("high".to_string());
            msgVec.push("Request from an IP not in the allowlist protocols.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 6: Geofencing
    if !check_any_ip_allowed(ip, SAFE_IPS, &["IN", "US"]).await {
        logs.push("[☠︎︎] Fourth malicious request detected. ".to_string());
        fallbacklogs.push(format!("Geofencing restriction applied for IP {}", ip));
        detected_threats.push("GeoRestricted IP".to_string());
        alert_type.push("Geofencing Restriction".to_string());
        severityVec.push("medium".to_string());
        msgVec.push("Request blocked due to geofencing rules voilation.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 7: HTTP Method Check
    let forbidden_methods = vec!["TRACE", "OPTIONS", "CONNECT"];
    if forbidden_methods.contains(&headers.method.as_str()) {
        logs.push("[☠︎︎] Fifth malicious request detected. ".to_string());
        fallbacklogs.push(format!("Disallowed HTTP method used: {}", headers.method));
        detected_threats.push("Disallowed HTTP Method".to_string());
        alert_type.push("Disallowed HTTP Method".to_string());
        severityVec.push("medium".to_string());
        msgVec.push("Request uses an HTTP method that is not allowed.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 8: Content-Type Check
    if let Some(ct) = &headers.content_type {
        let risky_types = vec!["multipart/form-data", "application/x-www-form-urlencoded"];
        if risky_types.iter().any(|t| ct.contains(t)) {
            logs.push("[☠︎︎] Sixth malicious request detected. ".to_string());
            fallbacklogs.push(format!("Suspicious Content-Type detected: {}", ct));
            detected_threats.push("Suspicious Content-Type".to_string());
            alert_type.push("Suspicious Content-Type".to_string());
            severityVec.push("medium".to_string());
            msgVec.push("Request has an unusual or disallowed Content-Type.".to_string());

            blocked = true;
            alert_status = true;
        }
    }

    // Step 9: Rate limiting
    let max_requests = filters
        .rate_limit
        .as_deref()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);

    let over_limit = {
        let mut limiter = RATE_LIMITER.lock().unwrap();
        let now = Instant::now();
        let entry = limiter.entry(ip.clone()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() > 60 {
            *entry = (1, now);
            false
        } else {
            entry.0 += 1;
            entry.0 > max_requests
        }
    };

    if over_limit {
        if &admin_email == "ganeshtelore4@gmail.com" {
            blocked = false;
        } else {
            logs.push("[☠︎︎] Rate limit exceeded for your api try again after a minute.".to_string());
            fallbacklogs.push(format!("Rate limit exceeded for IP {}", ip));
            detected_threats.push("Rate Limit Exceeded".to_string());
            alert_type.push("Rate Limit Exceeded".to_string());
            severityVec.push("high".to_string());
            msgVec.push("Request exceeds the allowed rate limit.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 10: User-Agent Check
    if headers.user_agent.is_empty() || headers.user_agent.len() > 512 {
        logs.push("[☠︎︎] Seventh malicious request detected. ".to_string());
        fallbacklogs.push("Suspicious User-Agent detected".to_string());
        detected_threats.push("Invalid User-Agent".to_string());
        alert_type.push("Invalid User-Agent".to_string());
        severityVec.push("medium".to_string());
        msgVec.push("Request contains an invalid or suspicious User-Agent.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 11: Pattern Matching
    let request_str = format!("{} {}", headers.method, headers.uri);
    let patterns = vec![
        r"(?i)\bunion\s+select\b",
        r"(?i)\bselect\s.+\sfrom\b",
        r"(?i)\binsert\s+into\b",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\bupdate\s+\w+\s+set\b",
        r"(?i)\bdelete\s+from\b",
        r"(?i)or\s+1\s*=\s*1",
        r"(?i)'--",
        r"(?i)'\s+or\s+'.+'='",
        r"(?i)\bexec(\s|\+)+(s|x)p\w+",
        r"(?i)<script.*?>.*?</script>",
        r"(?i)<.*?on\w+\s*=.*?>",
        r"(?i)<iframe.*?>",
        r"(?i)<img\s+src\s*=.*?onerror\s*=.*?>",
        r"(?i)javascript:",
        r"(?i)document\.cookie",
        r"(?i)alert\s*\(",
        r"\.\./\.\./",
        r"(?i)/etc/passwd",
        r"(?i)/boot.ini",
        r"(?i)\\windows\\win.ini",
        r"(?i);\s*shutdown",
        r"(?i);\s*reboot",
        r"(?i)&\s*rm\s+-rf\s+/",
        r"(?i)\s*nc\s+.*?-e\s+/bin/sh",
        r"(?i)wget\s+http",
        r"(?i)curl\s+http",
        r"(?i)base64_decode",
        r"(?i)php://input",
        r"(?i)data:text/html",
        r"(?i)file://",
        r"(?i)http[s]?://.*?\.(php|txt|html|sh|js)",
        r"(?i)0x[0-9a-fA-F]+",
        r"(?i)\bpasswd\b",
        r"(?i)\bconfig\.php\b",
        r"(?i)\benv\b",
        r"%0a",
        r"%0d",
        r"\r",
        r"\n",
    ];

    for pat in &patterns {
        if Regex::new(pat).unwrap().is_match(&request_str) {
            logs.push("[☠︎︎] Eight'th malicious request detected. ".to_string());
            fallbacklogs.push(format!("Threat pattern detected: {}", pat));
            detected_threats.push(pat.to_string());
            alert_type.push("Threat Pattern Detected".to_string());
            severityVec.push("high".to_string());
            msgVec.push("Request matches a known malicious pattern.".to_string());

            blocked = true;
            alert_status = true;
        }
    }

    if fallbacklogs.is_empty() {
        fallbacklogs.push("No anomalies detected in request.".to_string());
    }
    if detected_threats.is_empty() {
        detected_threats.push(
            "No threats detected by the Ethixion Threat Detection Engine. Your application appears secure.".to_string(),
        );
    }

    let redirect_url = headers.redirect_url.clone();
    let origin_url = headers.origin_url.clone();

    match make_request_log(
        &req_id,
        &admin_email,
        &headers.apiname,
        &origin_url,
        if blocked { "" } else { &redirect_url },
        !blocked,
        fallbacklogs.clone(),
        ip,
        &headers.user_agent,
        &detected_threats,
    )
    .await
    {
        Ok(_) => println!("[✔] Request log inserted into DB."),
        Err(e) => eprintln!("[❌] Failed to insert request log: {:?}", e),
    }

    match insert_api_alert(
        &admin_email,
        &headers.apiname,
        &req_id,
        &alert_type,
        &severityVec,
        &msgVec,
        "pending",
    )
    .await
    {
        Ok(_) => println!("[✔] Request log inserted into DB."),
        Err(e) => eprintln!("[❌] Failed to insert request log: {:?}", e),
    }

    println!("\n");
    for logs in &fallbacklogs {
        println!("{}", logs);
    }
    println!("[***] Ethixion security checks completed.");

    if blocked {
        return Json(GatekeeperResponse {
            status: false,
            redirect_url: "".to_string(),
            origin_url,
            logs,
        });
    }

    Json(GatekeeperResponse {
        status: true,
        redirect_url,
        origin_url,
        logs,
    })
}

#[post("/auth", data = "<payload>")]
async fn api_authorization_handler(
    payload: Json<APIURLHeaders>,
    pool: &State<PgPool>,
) -> Json<serde_json::Value> {
    match retrieve_apikey(&payload.apiname).await {
        Ok(mykey) => {
            if verify_password(&mykey, &payload.apikey) {
                Json(json!({"status": true, "msg": "Credentials validated successfully."}))
            } else {
                Json(json!({"status": false, "msg": "Invalid API key or API Name."}))
            }
        }
        Err(e) => Json(json!({"status": "Error", "msg": "Invalid credentials entered."})),
    }
}

// Ethixion HTTP Request Scanning Funcs -------------------------------------------------------

#[derive(Serialize)]
struct GatekeeperResponseII {
    status: bool,
    redirect_url: String,
    origin_url: String,
    logs: Vec<String>,
    body: Option<String>,
}

#[derive(FromForm, Debug, Serialize)]
pub struct APIForm {
    pub apiname: String,
    pub apikey: String,
    pub bodies: Option<Vec<String>>,
    pub target_url: String,
    pub origin_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestData {
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
    pub raw_headers: Vec<(String, String)>,
    pub suspicious: bool,
    pub matched_pattern: Option<String>,
    pub redirect_url: String,
    pub origin_url: String,
    pub bodies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct APIHTTPRequestInfo {
    pub headers: HttpRequestData,
    pub raw_headers: Vec<(String, String)>,
}

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for HttpRequestData {
    type Error = ();

    async fn from_request(
        req: &'r rocket::Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        let headers = req.headers();
        let total_headers = headers.len();

        let client_ip = req
            .client_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());

        let raw_headers: Vec<(String, String)> = headers
            .iter()
            .map(|h| (h.name.as_str().to_string(), h.value.to_string()))
            .collect();

        rocket::request::Outcome::Success(HttpRequestData {
            apiname: headers
                .get_one("x-api-name")
                .unwrap_or_default()
                .to_string(),
            apikey: headers.get_one("x-api-key").unwrap_or_default().to_string(),
            client_ip,
            method: req.method().as_str().to_string(),
            uri: req.uri().to_string(),
            user_agent: headers
                .get_one("User-Agent")
                .unwrap_or_default()
                .to_string(),
            host: headers.get_one("Host").unwrap_or_default().to_string(),
            referer: headers.get_one("Referer").map(|s| s.to_string()),
            content_type: req.content_type().map(|ct| ct.to_string()),
            content_length: headers
                .get_one("Content-Length")
                .and_then(|cl| cl.parse().ok()),
            total_headers,
            raw_headers,
            suspicious: false,
            matched_pattern: None,
            redirect_url: "".to_string(),
            origin_url: "".to_string(),
            bodies: vec![], // empty initially
        })
    }
}

// -------------------- Validate headers --------------------
pub async fn validate_headersII(
    request_data: &APIHTTPRequestInfo,
    req_id: &str,
    admin_email: &str,
    logs: &mut Vec<String>,
    fallbacklogs: &mut Vec<String>,
    detected_threats: &mut Vec<String>,
    alert_type: &mut Vec<String>,
    severity_vec: &mut Vec<String>,
    msg_vec: &mut Vec<String>,
) -> Option<GatekeeperResponseII> {
    let max_total_header_size: usize = 8192;
    let max_header_count: usize = 100;

    let mut total_size = 0;
    for (name, value) in &request_data.raw_headers {
        total_size += name.len() + value.len() + 4;
    }

    if total_size > max_total_header_size {
        logs.push(format!(
            "[✘] Total header size exceeded ({} > {} bytes)",
            total_size, max_total_header_size
        ));
        fallbacklogs.push("Total request headers size too large".to_string());
        detected_threats.push("Total Header Size Exceeded".to_string());
        alert_type.push("Header Size Violation".to_string());
        severity_vec.push("high".to_string());
        msg_vec.push("Combined HTTP headers exceeded safe processing limit.".to_string());

        return Some(GatekeeperResponseII {
            status: false,
            redirect_url: "".to_string(),
            origin_url: request_data.headers.origin_url.clone(),
            logs: logs.clone(),
            body: None,
        });
    }

    if request_data.raw_headers.len() > max_header_count {
        logs.push(format!(
            "[✘] Too many headers sent in request ({} > {} allowed)",
            request_data.raw_headers.len(),
            max_header_count
        ));
        fallbacklogs.push("Too many headers in request".to_string());
        detected_threats.push("Excessive Header Count".to_string());
        alert_type.push("Header Flood".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("Request exceeded maximum allowed number of headers.".to_string());

        return Some(GatekeeperResponseII {
            status: false,
            redirect_url: "".to_string(),
            origin_url: request_data.headers.origin_url.clone(),
            logs: logs.clone(),
            body: None,
        });
    }

    None
}

#[post("/ethix_auth", data = "<payload>")]
pub async fn ethix_auth(mut request_data: HttpRequestData, payload: Form<APIForm>) -> Template {
    let apidata = payload.into_inner();

    request_data.apiname = apidata.apiname.clone();
    request_data.apikey = apidata.apikey.clone();
    request_data.redirect_url = apidata.target_url.clone();
    request_data.origin_url = apidata
        .origin_url
        .unwrap_or_else(|| "http://ethicaldude.website3.me".to_string());

    // populate multiple bodies
    request_data.bodies = apidata.bodies.unwrap_or_default();

    let gatekeeper_result = ethix_gatekeeperII(&mut request_data).await;

    Template::render(
        "ethixionPage",
        context! {
            status: gatekeeper_result.status,
            redirect_url: gatekeeper_result.redirect_url,
            origin_url: gatekeeper_result.origin_url,
            logs: gatekeeper_result.logs,
            body: gatekeeper_result.body,
        },
    )
}

pub fn scan_request_bodies(bodies: &[String]) -> (bool, Vec<String>) {
    let mut blocked = false;
    let mut detected_threats = vec![];

    for (i, body) in bodies.iter().enumerate() {
        let (b_blocked, b_threats) = scan_request_body(body); // reuse existing single-body scanner
        if b_blocked {
            blocked = true;
        }
        for threat in b_threats {
            detected_threats.push(format!("Body[{}]: {}", i, threat));
        }
    }

    (blocked, detected_threats)
}

pub fn scan_request_body(body: &str) -> (bool, Vec<String>) {
    let mut blocked = false;
    let mut detected_threats = vec![];

    // Normalize body: decode percent-encoded and lower-case for easier matching
    let normalized_body = percent_decode_str(body).decode_utf8_lossy().to_lowercase();

    // 1️⃣ SQL Injection patterns
    let sqli_patterns = vec![
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"--",
        r";\s*drop\s+table",
        r"insert\s+into",
        r"update\s+\w+\s+set",
        r"delete\s+from",
    ];
    for pat in sqli_patterns {
        if Regex::new(pat).unwrap().is_match(&normalized_body) {
            detected_threats.push(format!("SQL Injection detected: {}", pat));
            blocked = true;
        }
    }

    // 2️⃣ XSS patterns
    let xss_patterns = vec![
        r"<script.*?>",
        r"onerror\s*=",
        r"javascript:",
        r"document\.cookie",
        r"alert\s*\(",
        r"<iframe.*?>",
        r"<img\s+src\s*=.*?onerror\s*=",
    ];
    for pat in xss_patterns {
        if Regex::new(pat).unwrap().is_match(&normalized_body) {
            detected_threats.push(format!("XSS detected: {}", pat));
            blocked = true;
        }
    }

    // 3️⃣ OS/Command Injection
    let os_injection = vec![";", "&&", "`", r"\|", "nc ", "curl ", "wget "];
    for pat in os_injection {
        if normalized_body.contains(pat) {
            detected_threats.push(format!("Command Injection detected: {}", pat));
            blocked = true;
        }
    }

    // 4️⃣ Code/Template Injection
    let code_injection = vec![r"\{\{.*?\}\}", r"<%.*?%>"];
    for pat in code_injection {
        if Regex::new(pat).unwrap().is_match(&normalized_body) {
            detected_threats.push(format!("Code/Template Injection detected: {}", pat));
            blocked = true;
        }
    }

    // 5️⃣ RFI/LFI
    let file_include_patterns = vec![r"http[s]?://.*\.php", r"\.\./"];
    for pat in file_include_patterns {
        if Regex::new(pat).unwrap().is_match(&normalized_body) {
            detected_threats.push(format!("File Inclusion/Path Traversal detected: {}", pat));
            blocked = true;
        }
    }

    // 6️⃣ Path Traversal (double-encoded)
    let traversal_patterns = vec![r"%2e%2e", r"%252e%252e"];
    for pat in traversal_patterns {
        if normalized_body.contains(pat) {
            detected_threats.push(format!("Encoded Path Traversal detected: {}", pat));
            blocked = true;
        }
    }

    // 7️⃣ Deserialization attacks
    let deserialization_patterns = vec![
        r"serialize\(",
        r"unserialize\(",
        r"pickle\(",
        r"java\.io\.Serializable",
    ];
    for pat in deserialization_patterns {
        if Regex::new(pat).unwrap().is_match(&normalized_body) {
            detected_threats.push(format!("Deserialization Attack detected: {}", pat));
            blocked = true;
        }
    }

    // 9️⃣ SSRF attempts
    let ssrf_patterns = vec!["169.254.169.254", "127.0.0.1", "localhost"];
    for pat in ssrf_patterns {
        if normalized_body.contains(pat) {
            detected_threats.push(format!("SSRF attempt detected: {}", pat));
            blocked = true;
        }
    }

    // 🔟 XXE attacks
    let xxe_patterns = vec!["<!entity", "<!doctype"];
    for pat in xxe_patterns {
        if normalized_body.contains(pat) {
            detected_threats.push(format!("XXE detected: {}", pat));
            blocked = true;
        }
    }

    // 11️⃣ Mass Assignment / Overposting
    if normalized_body.contains("isadmin") || normalized_body.contains("role=admin") {
        detected_threats.push("Mass Assignment / Overposting detected".to_string());
        blocked = true;
    }

    // 12️⃣ Large payloads / DoS
    if body.len() > 10_000 {
        // example threshold
        detected_threats.push("Large Payload / Possible DoS".to_string());
        blocked = true;
    }

    // 13️⃣ GraphQL abuse
    if normalized_body.contains("__schema") || normalized_body.contains("__type") {
        detected_threats.push("GraphQL introspection / abuse detected".to_string());
        blocked = true;
    }

    // 14️⃣ JSON/REST injection / malformed
    if normalized_body.starts_with("{") && normalized_body.ends_with("}") {
        if normalized_body.matches("{").count() > 50 {
            detected_threats.push("Deeply nested/malformed JSON detected".to_string());
            blocked = true;
        }
    }

    // 15️⃣ API abuse / automation (body repetition check example)
    if normalized_body.contains("rapid_test_payload") {
        detected_threats.push("Possible automated API abuse detected".to_string());
        blocked = true;
    }

    // 16️⃣ Business logic abuse
    if normalized_body.contains("\"price\":-") || normalized_body.contains("\"discount\":100") {
        detected_threats.push("Business Logic Abuse detected".to_string());
        blocked = true;
    }

    // 17️⃣ Encoding evasion
    if normalized_body.contains("%252e%252e") || normalized_body.contains("%255c") {
        detected_threats.push("Encoding Evasion detected".to_string());
        blocked = true;
    }

    (blocked, detected_threats)
}

// -------------------- Gatekeeper --------------------
pub async fn ethix_gatekeeperII(request_data: &mut HttpRequestData) -> GatekeeperResponseII {
    use chrono::Local;
    use regex::Regex;
    use std::time::Instant;

    let req_id = generate_request_id();
    let admin_email = retrieve_email_from_api(&request_data.apiname)
        .await
        .unwrap_or_else(|_| "admin@example.com".to_string());

    let mut logs = vec![];
    let mut fallbacklogs = vec![];
    let mut detected_threats = vec![];
    let mut alert_type = vec![];
    let mut severity_vec = vec![];
    let mut msg_vec = vec![];
    let mut blocked = false;
    let mut alert_status = false;

    // Step 0: Convert HttpRequestData -> APIHTTPRequestInfo
    let api_request_info = APIHTTPRequestInfo {
        headers: request_data.clone(),
        raw_headers: request_data.raw_headers.clone(),
    };

    // Step 0.1: Headers Validation
    if let Some(resp) = validate_headersII(
        &api_request_info,
        &req_id,
        &admin_email,
        &mut logs,
        &mut fallbacklogs,
        &mut detected_threats,
        &mut alert_type,
        &mut severity_vec,
        &mut msg_vec,
    )
    .await
    {
        return resp;
    }

    // Step 1: Retrieve stored API key
    let stored_key = match retrieve_apikey(&request_data.apiname).await {
        Ok(k) => k,
        Err(_) => {
            logs.push("[✘] Invalid API name".to_string());
            fallbacklogs.push("Invalid API name".to_string());
            alert_type.push("Invalid API Access".to_string());
            severity_vec.push("medium".to_string());
            msg_vec.push("Request attempted on a non-existent or invalid API.".to_string());

            let _ = make_request_log(
                &req_id,
                &admin_email,
                &request_data.apiname,
                &request_data.origin_url,
                "",
                false,
                fallbacklogs.clone(),
                &request_data.client_ip,
                &request_data.user_agent,
                &detected_threats,
            )
            .await;

            return GatekeeperResponseII {
                status: false,
                redirect_url: "".to_string(),
                origin_url: request_data.origin_url.clone(),
                logs,
                body: None,
            };
        }
    };

    // Step 2: Verify API key
    if !verify_password(&stored_key, &request_data.apikey) {
        logs.push("[✘] API key verification failed".to_string());
        fallbacklogs.push("API key mismatch".to_string());
        detected_threats.push("API key mismatch".to_string());
        alert_type.push("API Key Mismatch".to_string());
        severity_vec.push("high".to_string());
        msg_vec.push("API key provided did not match stored key.".to_string());
        blocked = true;

        let _ = make_request_log(
            &req_id,
            &admin_email,
            &request_data.apiname,
            &request_data.origin_url,
            "",
            false,
            fallbacklogs.clone(),
            &request_data.client_ip,
            &request_data.user_agent,
            &detected_threats,
        )
        .await;

        let _ = insert_api_alert(
            &admin_email,
            &request_data.apiname,
            &req_id,
            &alert_type,
            &severity_vec,
            &msg_vec,
            "pending",
        )
        .await;

        return GatekeeperResponseII {
            status: false,
            redirect_url: "".to_string(),
            origin_url: request_data.origin_url.clone(),
            logs,
            body: None,
        };
    } else {
        logs.push("[✔] API key verification passed.".to_string());
    }

    let ip = &request_data.client_ip;

    // Step 3: Check API active status
    match retrieve_api_isactive(&request_data.apiname).await {
        Ok(true) => logs.push("[✔] API is active.".to_string()),
        Ok(false) => {
            blocked = true;
            logs.push("[✘] API is disabled.".to_string());
            fallbacklogs.push("API disabled".to_string());
            alert_type.push("Disabled API Access".to_string());
            severity_vec.push("medium".to_string());
            msg_vec.push("Request attempted on a disabled API.".to_string());

            let subject = "Ethixion Firewall - Request Detected on Disabled API".to_string();
            let body = format!(
                "Request to API \"{}\" blocked at {} because the API is disabled.",
                &request_data.apiname,
                Local::now().format("%Y-%m-%d %H:%M:%S")
            );
            send_alert_email(&admin_email, &subject, &body).await;
        }
        Err(_) => {
            blocked = true;
            fallbacklogs.push("Error checking API status".to_string());
        }
    }

    // Step 4: Daily quota check
    if let Err(_) = map_api_daily_usage(&admin_email, &request_data.apiname).await {
        blocked = true;
        logs.push("[✘] Daily request limit reached.".to_string());
        fallbacklogs.push("Daily request limit reached.".to_string());
        alert_type.push("Daily Usage Limit Reached".to_string());
        severity_vec.push("high".to_string());
        msg_vec.push("User exceeded the daily API request quota.".to_string());

        let subject = "Ethixion Firewall - Daily API Request Limit Reached".to_string();
        let body = format!(
            "API \"{}\" has reached daily limit at {}.",
            &request_data.apiname,
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        send_alert_email(&admin_email, &subject, &body).await;
    }

    // Step 5: Retrieve filters
    let filters = match retrieve_predefined_filters(&request_data.apiname).await {
        Ok(Some(f)) => f,
        _ => {
            blocked = true;
            fallbacklogs.push("Could not load filter rules".to_string());
            return GatekeeperResponseII {
                status: false,
                redirect_url: "".to_string(),
                origin_url: request_data.origin_url.clone(),
                logs,
                body: None,
            };
        }
    };

    // Step 6: Header validation
    if request_data.host.is_empty() || request_data.host.len() > 256 {
        logs.push("[☠︎︎] Invalid Host header".to_string());
        fallbacklogs.push("Invalid or missing Host header".to_string());
        detected_threats.push("Missing/Invalid Host Header".to_string());
        alert_type.push("Missing/Invalid Host Header".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("The request contains a missing or invalid Host header.".to_string());
        blocked = true;
        alert_status = true;
    }

    if let Some(ref referer) = request_data.referer {
        if referer.contains("127.") || referer.contains("localhost") {
            logs.push("[☠︎︎] Suspicious referer header".to_string());
            fallbacklogs.push("Suspicious referer header.".to_string());
            detected_threats.push("Localhost Referer".to_string());
            alert_type.push("Suspicious Referer Header".to_string());
            severity_vec.push("medium".to_string());
            msg_vec
                .push("Referer header points to localhost; possible header tampering.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 7: IP allowlist
    if let Some(ref allowed_ip_str) = filters.allowed_ip {
        let allowed_ips: Vec<&str> = allowed_ip_str.split(',').map(|s| s.trim()).collect();
        if !allowed_ips.contains(&ip.as_str()) && !SAFE_IPS.contains(&ip.as_str()) {
            logs.push("[☠︎︎] IP not in allowlist".to_string());
            fallbacklogs.push(format!("IP {} not in allowlist", ip));
            detected_threats.push("IP Not in Allowlist".to_string());
            alert_type.push("IP Not in Allowlist".to_string());
            severity_vec.push("high".to_string());
            msg_vec.push("Request from an IP not in allowlist.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 8: Geofencing
    if !check_any_ip_allowed(ip, SAFE_IPS, &["IN", "US"]).await {
        logs.push("[☠︎︎] Geofencing violation".to_string());
        fallbacklogs.push(format!("Geofencing restriction applied for IP {}", ip));
        detected_threats.push("GeoRestricted IP".to_string());
        alert_type.push("Geofencing Restriction".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("Request blocked due to geofencing rules violation.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 9: HTTP method check
    let forbidden_methods = vec!["TRACE", "OPTIONS", "CONNECT"];
    if forbidden_methods.contains(&request_data.method.as_str()) {
        logs.push("[☠︎︎] Disallowed HTTP method".to_string());
        fallbacklogs.push(format!(
            "Disallowed HTTP method used: {}",
            request_data.method
        ));
        detected_threats.push("Disallowed HTTP Method".to_string());
        alert_type.push("Disallowed HTTP Method".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("Request uses HTTP method that is not allowed.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 10: Content-Type check
    /*if let Some(ct) = &request_data.content_type {
        let risky_types = vec!["multipart/form-data", "application/x-www-form-urlencoded"];
        if risky_types.iter().any(|t| ct.contains(t)) {
            logs.push("[☠︎︎] Suspicious Content-Type".to_string());
            fallbacklogs.push(format!("Suspicious Content-Type detected: {}", ct));
            detected_threats.push("Suspicious Content-Type".to_string());
            alert_type.push("Suspicious Content-Type".to_string());
            severity_vec.push("medium".to_string());
            msg_vec.push("Request has unusual or disallowed Content-Type.".to_string());
            blocked = true;
            alert_status = true;
        }
    }*/

    // Step 11: Rate limiting
    let max_requests = filters
        .rate_limit
        .as_deref()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);

    let over_limit = {
        let mut limiter = RATE_LIMITER.lock().unwrap();
        let now = Instant::now();
        let entry = limiter.entry(ip.clone()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() > 60 {
            *entry = (1, now);
            false
        } else {
            entry.0 += 1;
            entry.0 > max_requests
        }
    };

    if over_limit {
        if &admin_email != "ganeshtelore4@gmail.com" {
            logs.push("[☠︎︎] Rate limit exceeded".to_string());
            fallbacklogs.push(format!("Rate limit exceeded for IP {}", ip));
            detected_threats.push("Rate Limit Exceeded".to_string());
            alert_type.push("Rate Limit Exceeded".to_string());
            severity_vec.push("high".to_string());
            msg_vec.push("Request exceeds the allowed rate limit.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    // Step 12: User-Agent check
    if request_data.user_agent.is_empty() || request_data.user_agent.len() > 512 {
        logs.push("[☠︎︎] Invalid User-Agent".to_string());
        fallbacklogs.push("Suspicious User-Agent detected".to_string());
        detected_threats.push("Invalid User-Agent".to_string());
        alert_type.push("Invalid User-Agent".to_string());
        severity_vec.push("medium".to_string());
        msg_vec.push("Request contains invalid or suspicious User-Agent.".to_string());
        blocked = true;
        alert_status = true;
    }

    // Step 13: Threat pattern matching
    let request_str = format!("{} {}", request_data.method, request_data.uri);
    let patterns = vec![
        r"(?i)\bunion\s+select\b",
        r"(?i)\bselect\s.+\sfrom\b",
        r"(?i)\binsert\s+into\b",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\bupdate\s+\w+\s+set\b",
        r"(?i)\bdelete\s+from\b",
        r"(?i)or\s+1\s*=\s*1",
        r"(?i)'--",
        r"(?i)'\s+or\s+'.+'='",
        r"(?i)\bexec(\s|\+)+(s|x)p\w+",
        r"(?i)<script.*?>.*?</script>",
        r"(?i)<.*?on\w+\s*=.*?>",
        r"(?i)<iframe.*?>",
        r"(?i)<img\s+src\s*=.*?onerror\s*=.*?>",
        r"(?i)javascript:",
        r"(?i)document\.cookie",
        r"(?i)alert\s*\(",
        r"\.\./\.\./",
        r"(?i)/etc/passwd",
        r"(?i)/boot.ini",
        r"(?i)\\windows\\win.ini",
        r"(?i);\s*shutdown",
        r"(?i);\s*reboot",
        r"(?i)&\s*rm\s+-rf\s+/",
        r"(?i)\s*nc\s+.*?-e\s+/bin/sh",
        r"(?i)wget\s+http",
        r"(?i)curl\s+http",
        r"(?i)base64_decode",
        r"(?i)php://input",
        r"(?i)data:text/html",
        r"(?i)file://",
        r"(?i)http[s]?://.*?\.(php|txt|html|sh|js)",
        r"(?i)0x[0-9a-fA-F]+",
        r"(?i)\bpasswd\b",
        r"(?i)\bconfig\.php\b",
        r"(?i)\benv\b",
        r"%0a",
        r"%0d",
        r"\r",
        r"\n",
    ];

    for pat in &patterns {
        if Regex::new(pat).unwrap().is_match(&request_str) {
            logs.push("[☠︎︎] Threat pattern detected".to_string());
            fallbacklogs.push(format!("Threat pattern detected: {}", pat));
            detected_threats.push(pat.to_string());
            alert_type.push("Threat Pattern Detected".to_string());
            severity_vec.push("high".to_string());
            msg_vec.push("Request matches a known malicious pattern.".to_string());
            blocked = true;
            alert_status = true;
        }
    }

    if fallbacklogs.is_empty() {
        fallbacklogs.push("No anomalies detected in request.".to_string());
    }
    if detected_threats.is_empty() {
        detected_threats
            .push("No threats detected by the Ethixion Threat Detection Engine.".to_string());
    }

    // Step 14: Multi-body Threat Checkpoint
    let (body_blocked, body_threats) = scan_request_bodies(&request_data.bodies);

    if body_blocked {
        logs.extend(body_threats.clone());
        fallbacklogs.push("Body Threat Detected".to_string());
        detected_threats.extend(body_threats.clone());
        alert_type.push("Body Threat Detected".to_string());
        severity_vec.push("high".to_string());
        blocked = true;
    }

    if body_threats.is_empty() {
        detected_threats.push("No Threats Detected in Body Data.".to_string());
        fallbacklogs.push("No Threats Detected in Body Data.".to_string());
    }

    // Final logging
    let redirect_url = request_data.redirect_url.clone();
    let origin_url = request_data.origin_url.clone();

    println!("\n");
    for logs in &fallbacklogs {
        println!("{}", logs);
    }
    println!("[***] Ethixion security checks completed.");

    match make_request_log(
        &req_id,
        &admin_email,
        &request_data.apiname,
        &origin_url,
        if blocked { "" } else { &redirect_url },
        !blocked,
        fallbacklogs.clone(),
        ip,
        &request_data.user_agent,
        &detected_threats,
    )
    .await
    {
        Ok(_) => println!("[✔] Request log inserted into DB."),
        Err(e) => eprintln!("[❌] Failed to insert request log: {:?}", e),
    }

    match insert_api_alert(
        &admin_email,
        &request_data.apiname,
        &req_id,
        &alert_type,
        &severity_vec,
        &msg_vec,
        "pending",
    )
    .await
    {
        Ok(_) => println!("[✔] Request log inserted into DB."),
        Err(e) => eprintln!("[❌] Failed to insert request log: {:?}", e),
    }

    if blocked {
        return GatekeeperResponseII {
            status: false,
            redirect_url: "".to_string(),
            origin_url,
            logs,
            body: None,
        };
    }

    let encData = get_api_enc_key(&request_data.apiname, &admin_email).await;

    let body = encrypt_data(&request_data.bodies, &encData.unwrap().aes_key);

    GatekeeperResponseII {
        status: true,
        redirect_url,
        origin_url,
        logs,
        body: Some(match body {
            Ok((ciphertext_b64, nonce_b64)) => {
                // Create JSON object
                let json_payload = serde_json::json!({
                    "ciphertext": ciphertext_b64,
                    "nonce": nonce_b64
                })
                .to_string();

                // Base64 wrap JSON so it's safe for hidden input
                general_purpose::STANDARD.encode(json_payload)
            }
            Err(e) => e,
        }),
    }
}

#[get("/mydata")]
pub async fn myData() -> Json<serde_json::Value> {
    let key = generate_aes256_key();

    Json(json!({
        "status": "Success",
        "payload": key
    }))
}

#[derive(FromForm)]
pub struct GetData {
    pub ethix_payload: String,
    pub origin_url: Option<String>,
}

#[derive(Deserialize)]
struct DecodedPayload {
    pub ciphertext: String,
    pub nonce: String,
}

#[post("/getData", data = "<payload>")]
pub async fn getData(payload: Form<GetData>) -> Json<serde_json::Value> {
    let key = "BbJzXMHkVWcdovt3U3zFMJwIl6NGxdUlJa8ArqY9ovE="; // your AES key

    // Step 1: Base64 decode the received payload
    let decoded_bytes = match general_purpose::STANDARD.decode(&payload.ethix_payload) {
        Ok(b) => b,
        Err(_) => {
            return Json(serde_json::json!({
                "status": "Failed",
                "reason": "Invalid Base64"
            }));
        }
    };

    // Step 2: Convert bytes to string
    let decoded_string = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(_) => {
            return Json(serde_json::json!({
                "status": "Failed",
                "reason": "UTF-8 conversion error"
            }));
        }
    };

    // Step 3: Parse JSON to get ciphertext and nonce
    let decoded_payload: DecodedPayload = match serde_json::from_str(&decoded_string) {
        Ok(p) => p,
        Err(_) => {
            return Json(serde_json::json!({
                "status": "Failed",
                "reason": "Invalid payload JSON"
            }));
        }
    };

    // Step 4: Decrypt using AES-GCM
    let mtdata = match decrypt_data::<serde_json::Value>(
        &decoded_payload.ciphertext,
        &decoded_payload.nonce,
        key,
    ) {
        Ok(d) => d,
        Err(_) => {
            return Json(serde_json::json!({
                "status": "Failed",
                "reason": "Decryption failed"
            }));
        }
    };

    println!("Actual Payload from user: {:?}", mtdata);

    Json(serde_json::json!({
        "status": "Success",
        "payload": mtdata
    }))
}

#[launch]
async fn rocket() -> _ {
    let figment = Figment::from(Config::default())
        .merge(("address", "0.0.0.0"))
        .merge(("limits.data", 1 * 1024 * 1024))
        .merge(("limits.file", 2 * 1024 * 1024))
        .merge(("limits.form", 512 * 1024));
    let pool = db::init_global_pool().await;

    let cors = CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .expect("CORS configuration failed");

    rocket::custom(figment)
        .manage(pool.clone())
        //.mount("/static",FileServer::from("/home/ethicalgt/Pictures/ethixion_backend/static"),)
        .mount("/static", FileServer::from("static"))
        .mount(
            "/",
            routes![
                login_handler,
                google_auth_login,
                register_handler,
                verify_account,
                api_handler,
                validate_active_user,
                api_authorization_handler,
                ethix_gatekeeper_handler,
                ethix_auth,
                get_active_user_info,
                set_ethix_rules,
                get_todays_threat_logs,
                get_todays_dashboard_data,
                get_report_logs,
                get_dashboard_security_details,
                get_dashboard_trend_details,
                get_dashboard_trends_status,
                get_dashboard_adavnce_monitorings,
                get_api_overview,
                disable_api_req,
                enable_api_req,
                delete_api_req,
                regenerate_api_key,
                retrieve_api_alerts_handler,
                getData,
                myData,
            ],
        )
        .attach(cors)
        .attach(Template::fairing())
}
