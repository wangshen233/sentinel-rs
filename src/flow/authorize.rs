//! authorize 会话建立：warmup → signin → `auth_oauth_init`。
//!
//! 对齐 Python `协议/auth_flow.py` 的三步（顺序不能换）：
//!
//! ```text
//! warmup()          GET  https://chatgpt.com/api/auth/csrf        → 种 oai-did + csrfToken
//! get_auth_url()    POST https://chatgpt.com/api/auth/signin/openai → authorize URL（带 login_hint）
//! auth_oauth_init() GET  <authorize URL>（跟随 302，整套浏览器头） → 落地 URL + 会话 state
//! ```
//!
//! ### 为什么必须有这一步
//! Python 原话（`auth_flow.py:2352-2397`）：
//! > 这一步**建立的就是后面要用的那个 state**，头不像真浏览器就拿不到有效状态，
//! > 下一步必 409 invalid_state。
//!
//! 只 POST `authorize/continue` 是 **Python 已废弃的旧路径**（当前 0 次调用）：
//! 邮箱靠 signin 的 `login_hint` 透传进 authorize URL，authorize 这一跳直接把邮箱
//! 送达，落 `/email-verification`；`user/register` 等后续请求消费的正是这一跳建立的
//! 会话。裸头（只发 Accept/Referer/UA）实测 409 = 3/6，补齐 client hints +
//! 整组 `Sec-Fetch-*` 后 409 = 0。
//!
//! ### 与 Python 的一处差异
//! Python 用 `session.get(..., allow_redirects=True)` 让 requests 自己跟随；
//! 本 crate 的 [`super::http::Client`] 故意 `redirect(none)`（注册链要看 302 的
//! Location），所以这里**手动逐跳跟随**并把落地 URL 记下来 —— 等价且更可控。

use super::auth::{self, AuthRequestBuilder};
use super::http;
use anyhow::{bail, Context, Result};
use std::time::Duration;
use tracing::{debug, info, warn};

/// warmup 最多试几次（Python 侧单次成功率约 24%，多试是唯一手段）。
pub const WARMUP_ATTEMPTS: u32 = 4;
/// authorize 链最多跟几跳（正常 2~3 跳：authorize → email-verification）。
pub const MAX_AUTHORIZE_HOPS: usize = 8;

/// warmup 的产出：`csrfToken` + 服务端下发的 `oai-did`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Warmup {
    pub csrf_token: String,
    /// **必须**是 cookie 里这个值，不能凭空 uuid4（Python `_resolve_device_id`）。
    pub device_id: String,
    pub attempts: u32,
}

/// `GET https://chatgpt.com/api/auth/csrf`：种 `oai-did`，同时拿到 `csrfToken`。
///
/// 判据只看 cookie jar 里有没有 `oai-did`（Python warmup docstring：
/// 「判据改成直接查 cookie jar，这是唯一可信的信号」，403 也可能 return True）。
pub async fn warmup(http: &http::Client, builder: &AuthRequestBuilder) -> Result<Warmup> {
    info!("[1/10] warmup：GET chatgpt.com/api/auth/csrf（种 oai-did）...");
    let mut last_error = String::from("尚未发送请求");

    for attempt in 1..=WARMUP_ATTEMPTS {
        let spec = builder.warmup_spec();
        match http.execute(&spec).await {
            Ok(resp) => {
                let status = resp.status;
                if !(200..300).contains(&status) {
                    last_error = format!(
                        "HTTP {status}: {}",
                        resp.body.chars().take(160).collect::<String>()
                    );
                    warn!("[warmup] 第 {attempt}/{WARMUP_ATTEMPTS} 次失败: {last_error}");
                } else {
                    match auth::parse_csrf_token(&resp.body) {
                        Ok(csrf_token) => {
                            let device_id = auth::cookie_value(
                                &http.cookie_header_for(auth::CHATGPT_BASE),
                                "oai-did",
                            )
                            .unwrap_or_default();
                            if device_id.is_empty() {
                                last_error =
                                    format!("csrf 200 但 cookie jar 里没有 oai-did（第 {attempt} 次）");
                                warn!("[warmup] {last_error}");
                            } else {
                                info!(
                                    "[warmup] ok（第 {attempt} 次）oai-did={}… csrf={}B",
                                    &device_id[..device_id.len().min(8)],
                                    csrf_token.len()
                                );
                                return Ok(Warmup {
                                    csrf_token,
                                    device_id,
                                    attempts: attempt,
                                });
                            }
                        }
                        Err(err) => {
                            last_error = format!("{err:#}");
                            warn!("[warmup] 第 {attempt}/{WARMUP_ATTEMPTS} 次失败: {last_error}");
                        }
                    }
                }
            }
            Err(err) => {
                last_error = format!("{err:#}");
                warn!("[warmup] 第 {attempt}/{WARMUP_ATTEMPTS} 次请求失败: {last_error}");
            }
        }
        if attempt < WARMUP_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
    }

    bail!(
        "warmup 失败：{WARMUP_ATTEMPTS} 次都没拿到 chatgpt.com 的 oai-did cookie（最后错误: {last_error}）。\
         没有 oai-did 的会话在 signin 阶段拿不到 authorize URL，继续注册必然 409 invalid_state；\
         多为代理出口 IP 不通或被 CF 拦，请检查代理后重试"
    )
}

/// `POST /api/auth/signin/openai` → authorize URL（已补齐上下文参数）。
pub async fn fetch_authorize_url(
    http: &http::Client,
    builder: &AuthRequestBuilder,
    email: &str,
    csrf_token: &str,
    device_id: &str,
) -> Result<String> {
    info!("[2/10] 获取 authorize URL（signin/openai，login_hint 走 query）...");
    let spec = builder.signin_openai_spec(
        email,
        csrf_token,
        device_id,
        builder.auth_session_logging_id(),
    );
    let resp = http.execute(&spec).await.context("signin/openai 请求失败")?;
    if !resp.is_success() {
        bail!(
            "signin/openai 返回 HTTP {}: {}",
            resp.status,
            resp.body.chars().take(400).collect::<String>()
        );
    }
    let raw = auth::parse_signin_url(&resp.body)?;
    let url = auth::ensure_authorize_context(
        &raw,
        email,
        device_id,
        builder.auth_session_logging_id(),
    );
    debug!("[signin] authorize URL: {}", redact(&url));
    info!(
        "[signin] authorize URL 就绪：{}B，login_hint={} ccaps={}",
        url.len(),
        url.contains("login_hint"),
        url.contains("ccaps")
    );
    Ok(url)
}

/// `auth_oauth_init` 的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizeInit {
    /// 跟随 302 之后的最终落地 URL（signup 的**唯一**判据）。
    pub landing_url: String,
    /// 本次会话的 `oai-did`（cookie 优先，HTML 兜底）。
    pub device_id: String,
    /// 最后一跳的 HTTP 状态码。
    pub final_status: u16,
    /// 每跳的 `状态码 路径`，用于报告里贴状态码序列。
    pub hops: Vec<String>,
}

/// GET authorize URL，跟随重定向链，记录落地 URL + `oai-did`。
///
/// 头来自 [`AuthRequestBuilder::authorize_init_spec`]（整页导航 + cross-site +
/// 全套 client hints），这正是 Python `_navigation_headers` 那套。
pub async fn auth_oauth_init(
    http: &http::Client,
    builder: &AuthRequestBuilder,
    authorize_url: &str,
    cookie_device_id: &str,
) -> Result<AuthorizeInit> {
    info!("[3/10] OAuth 初始化：GET authorize（浏览器头 + 跟随重定向）...");
    let mut current = authorize_url.trim().to_string();
    let mut hops: Vec<String> = Vec::new();
    let mut final_status = 0u16;
    let mut final_body = String::new();

    for hop in 1..=MAX_AUTHORIZE_HOPS {
        let spec = builder.authorize_init_spec(&current);
        let resp = http
            .execute(&spec)
            .await
            .with_context(|| format!("第 {hop} 跳请求失败: {}", redact(&current)))?;
        final_status = resp.status;
        hops.push(format!("{} {}", resp.status, url_path(&current)));
        debug!(
            "[authorize] hop {hop}: {} {} -> {}B",
            resp.status,
            url_path(&current),
            resp.body.len()
        );

        if (300..400).contains(&resp.status) {
            let location = resp.header("location").map(str::trim).unwrap_or("");
            if location.is_empty() {
                warn!("[authorize] 第 {hop} 跳 {} 但没有 Location，停止跟随", resp.status);
                final_body = resp.body.clone();
                break;
            }
            let next = auth::absolute_url(location, &current);
            debug!("[authorize] 第 {hop} 跳 {} Location → {}", resp.status, redact(&next));
            current = next;
            continue;
        }

        if resp.status >= 400 {
            warn!(
                "[authorize] 落地非 2xx：{}（{}）body={}",
                resp.status,
                url_path(&current),
                resp.body.chars().take(300).collect::<String>()
            );
        }
        final_body = resp.body.clone();
        break;
    }

    let landing_url = current;
    if landing_url.is_empty() {
        bail!("authorize 落地 URL 为空（跟随 {} 跳后仍无 URL）", hops.len());
    }

    // oai-did：cookie 优先（warmup 种的和 auth 域下发的都看），HTML 最后兜底。
    let device_id = {
        let from_chatgpt = auth::cookie_value(
            &http.cookie_header_for(auth::CHATGPT_BASE),
            "oai-did",
        );
        let from_auth = auth::cookie_value(&http.cookie_header_for(auth::AUTH_BASE), "oai-did");
        from_chatgpt
            .or(from_auth)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| auth::device_id_from_html(&final_body))
            .unwrap_or_else(|| cookie_device_id.trim().to_string())
    };
    if device_id.trim().is_empty() {
        bail!("authorize 之后仍拿不到 oai-did（cookie 与 HTML 都没有），无法继续");
    }

    // 这一次是整页文档导航 → 铸新的 document-navigation-id（给随后的 JSON POST 用）。
    builder.new_document_navigation();

    info!(
        "[authorize] 落地: {}（{} 跳: {}）",
        redact(&landing_url),
        hops.len(),
        hops.join(" → ")
    );

    Ok(AuthorizeInit {
        landing_url,
        device_id,
        final_status,
        hops,
    })
}

/// URL 里的路径部分（日志用；不打印 query，避免把 code/state 带进日志）。
fn url_path(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    match without_scheme.split_once('/') {
        Some((_host, path)) => format!("/{}", path.split(['?', '#']).next().unwrap_or("")),
        None => without_scheme.to_string(),
    }
}

/// 日志里只保留 host+path（query 里有 state / login_hint，属于敏感信息）。
fn redact(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(without_scheme);
    format!("https://{}{}", host, url_path(url))
}
