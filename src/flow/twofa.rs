//! TOTP（RFC 6238）与 2FA enroll / activate 请求构造。
//!
//! 对齐 Python `协议/protocol_runtime/two_factor.py`：
//!   * `GET  https://chatgpt.com/backend-api/accounts/mfa_info`
//!   * `POST .../mfa/enroll`                  body `{"factor_type":"totp"}`
//!   * `POST .../mfa/user/activate_enrollment` body `{"code","factor_type","session_id"}`
//!
//! TOTP 实现与 Python 的 `hotp()` 完全一致：HMAC-SHA1 + base32 secret + 30s 步长。

use super::auth::AuthRequestBuilder;
use super::http::{Method, RequestSpec};
use super::SentinelToken;
use anyhow::{bail, Context, Result};
use base32::Alphabet;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;

pub const MFA_BASE: &str = "https://chatgpt.com/backend-api/accounts";
pub const OTP_DIGITS: u32 = 6;
pub const OTP_PERIOD_SECS: u64 = 30;

// ─────────────────────────── TOTP ───────────────────────────

/// base32 secret → 原始字节（容忍空格/短横线/小写/无 padding）。
pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        bail!("TOTP secret 为空");
    }
    let padded = format!("{}{}", cleaned, "=".repeat((8 - cleaned.len() % 8) % 8));
    base32::decode(Alphabet::Rfc4648 { padding: true }, &padded)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: false }, &cleaned))
        .with_context(|| format!("TOTP secret 不是合法 base32: {secret}"))
}

/// RFC 4226 HOTP。
pub fn hotp(secret_b32: &str, counter: u64, digits: u32) -> Result<String> {
    let key = decode_secret(secret_b32)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).context("HMAC-SHA1 初始化失败")?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    if digest.len() < 20 {
        bail!("HMAC-SHA1 输出长度异常: {}", digest.len());
    }
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let code = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10u32.pow(digits);
    Ok(format!("{:0width$}", code % modulo, width = digits as usize))
}

/// RFC 6238 TOTP（自定义时间点，便于用已知向量测试）。
pub fn totp_at(secret_b32: &str, unix_secs: u64, digits: u32, period_secs: u64) -> Result<String> {
    if period_secs == 0 {
        bail!("TOTP period 必须 > 0");
    }
    hotp(secret_b32, unix_secs / period_secs, digits)
}

/// 当前时间的 6 位 TOTP。
pub fn totp_now(secret_b32: &str) -> Result<String> {
    totp_at(secret_b32, now_secs(), OTP_DIGITS, OTP_PERIOD_SECS)
}

/// 校验验证码，允许 ±1 个时间窗（对齐 Python `verify_totp`）。
pub fn verify_totp_at(secret_b32: &str, code: &str, unix_secs: u64) -> Result<bool> {
    let counter = unix_secs / OTP_PERIOD_SECS;
    for delta in [-1i64, 0, 1] {
        let shifted = (counter as i64 + delta).max(0) as u64;
        if hotp(secret_b32, shifted, OTP_DIGITS)? == code {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 用当前时间校验。
pub fn verify_totp(secret_b32: &str, code: &str) -> Result<bool> {
    verify_totp_at(secret_b32, code, now_secs())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─────────────────────────── 响应模型 ───────────────────────────

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Factor {
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct EnrollResponse {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub factor: Option<Factor>,
}

impl EnrollResponse {
    pub fn factor_id(&self) -> &str {
        self.factor.as_ref().map(|f| f.id.as_str()).unwrap_or("")
    }
}

/// `GET mfa_info` 响应。
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct MfaInfoResponse {
    #[serde(default)]
    pub mfa_enabled: bool,
    #[serde(default)]
    pub factors: Option<MfaFactors>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct MfaFactors {
    #[serde(default)]
    pub totp: Option<Factor>,
}

/// 解析 enroll 响应；`secret`/`session_id` 缺一即报错（与 Python 一致）。
pub fn parse_enroll(body: &str) -> Result<EnrollResponse> {
    let parsed: EnrollResponse =
        serde_json::from_str(body).context("mfa/enroll 响应不是合法 JSON")?;
    if parsed.secret.trim().is_empty() || parsed.session_id.trim().is_empty() {
        bail!("mfa/enroll 响应缺 secret/session_id");
    }
    Ok(parsed)
}

/// 解析 `mfa_info` 响应。
pub fn parse_mfa_info(body: &str) -> Result<MfaInfoResponse> {
    serde_json::from_str(body).context("mfa_info 响应不是合法 JSON")
}

/// 已经绑过 TOTP 就不要再 enroll（secret 取不回来）。
pub fn already_enrolled(info: &MfaInfoResponse) -> bool {
    info.mfa_enabled && info.factors.as_ref().and_then(|f| f.totp.as_ref()).is_some()
}

// ─────────────────────────── 请求构造 ───────────────────────────

fn mfa_headers(builder: &AuthRequestBuilder, referer: &str, access_token: &str) -> Vec<(String, String)> {
    vec![
        ("accept".to_string(), "application/json".to_string()),
        (
            "authorization".to_string(),
            format!("Bearer {access_token}"),
        ),
        ("referer".to_string(), referer.to_string()),
        ("origin".to_string(), "https://chatgpt.com".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        (
            "accept-language".to_string(),
            builder.accept_language().to_string(),
        ),
    ]
}

/// `GET /mfa_info`
pub fn mfa_info_spec(
    builder: &AuthRequestBuilder,
    access_token: &str,
    _st: &SentinelToken,
) -> RequestSpec {
    let url = format!("{MFA_BASE}/mfa_info");
    RequestSpec {
        label: "2fa.mfa_info",
        method: Method::Get,
        url: url.clone(),
        headers: mfa_headers(builder, &url, access_token),
        body: None,
        raw_body: None,
    }
}

/// `POST /mfa/enroll`
pub fn enroll_spec(
    builder: &AuthRequestBuilder,
    access_token: &str,
    _st: &SentinelToken,
) -> RequestSpec {
    let url = format!("{MFA_BASE}/mfa/enroll");
    RequestSpec::post_json(
        "2fa.enroll",
        url.clone(),
        Some(mfa_headers(builder, &url, access_token)),
        Some(json!({ "factor_type": "totp" })),
    )
}

/// `POST /mfa/user/activate_enrollment`
pub fn activate_spec(
    builder: &AuthRequestBuilder,
    access_token: &str,
    code: &str,
    session_id: &str,
    _st: &SentinelToken,
) -> RequestSpec {
    let url = format!("{MFA_BASE}/mfa/user/activate_enrollment");
    RequestSpec::post_json(
        "2fa.activate",
        url.clone(),
        Some(mfa_headers(builder, &url, access_token)),
        Some(json!({
            "code": code,
            "factor_type": "totp",
            "session_id": session_id,
        })),
    )
}
