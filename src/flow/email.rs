//! 通用邮箱取码 API 客户端（纯 HTTP 契约，不绑定任何具体服务 / 私有凭据）。
//!
//! ### 环境变量
//! * `REG_MAIL_API_BASE_URL`（必填）—— 邮箱服务基地址，默认必须 `https://`。
//!   明文 `http://`（任意 host，含自建 `http://IP:PORT`）只有在显式设置
//!   `REG_MAIL_ALLOW_INSECURE=1` 时才放行，且每次进程只打印一次明文告警。
//! * `REG_MAIL_API_TOKEN`（可选）—— 非空时作为 `Authorization: Bearer <token>` 发送。
//! * `REG_MAIL_EMAIL_FILE`（可选）—— **静态邮箱池**文件，见
//!   [`StaticEmailPool`]。设置后走"固定邮箱 + 取码链接"模式：
//!   **不调用** `POST /mailboxes`，按行取现成邮箱，取码仍走 `GET {code_url}`。
//!   与 `REG_MAIL_API_*` 互斥，静态池优先。
//! * `REG_MAIL_ALLOW_INSECURE`（可选）—— `1` 时放行**任意 host** 的明文
//!   `http://`（`code_url` 与 `base_url` 同一开关）；未开启时明文 http 一律拒绝。
//!
//! ### 契约
//! * `POST {base}/mailboxes` → `201 {"email": "...", "code_url": "https://..."}`
//! * `GET  {code_url}`       → 取码页 HTML（最新在前，`<article>` 卡片里
//!   `<div class="meta">时间：…</div>` + `<div class="code">123456</div>`），
//!   **或** JSON（`{"code":"123456",...}` / `{"code":"no_code",...}`）
//! * `GET  {base}/health`    → 可选自检 `{"ok": true}`，只在 dry-run 请求计划里出现
//!
//! 取码逻辑复用 [`super::otp`]，本文件只做 "取 HTML/JSON"。

use super::http::{Client, RequestSpec};
use super::otp;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub const ENV_BASE_URL: &str = "REG_MAIL_API_BASE_URL";
pub const ENV_TOKEN: &str = "REG_MAIL_API_TOKEN";
pub const ENV_ALLOW_INSECURE: &str = "REG_MAIL_ALLOW_INSECURE";
/// 静态邮箱池文件（每行 `email----code_url`）。
pub const ENV_EMAIL_FILE: &str = "REG_MAIL_EMAIL_FILE";
/// 静态池里 `email` 与 `code_url` 的分隔符（4 个连字符）。
pub const STATIC_EMAIL_SEPARATOR: &str = "----";

/// 邮箱 API 基地址 + 可选 bearer token。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailApiConfig {
    pub base_url: String,
    /// 空字符串表示服务端不需要鉴权（不发送 `Authorization` 头）。
    pub token: String,
    /// `REG_MAIL_ALLOW_INSECURE=1`：放行任意 host 的明文 `http://`。
    pub allow_insecure: bool,
}

impl EmailApiConfig {
    /// 从可注入的读取器解析；`REG_MAIL_API_BASE_URL` 缺失时返回 `Ok(None)`。
    pub fn from_lookup<F>(lookup: &F) -> Result<Option<Self>>
    where
        F: Fn(&str) -> Option<String> + ?Sized,
    {
        let get = |key: &str| {
            lookup(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let allow_insecure = is_truthy(get(ENV_ALLOW_INSECURE).as_deref());
        match (get(ENV_BASE_URL), get(ENV_TOKEN)) {
            (Some(base), token) => Ok(Some(Self::validated(
                base,
                token.unwrap_or_default(),
                allow_insecure,
            )?)),
            (None, Some(_)) => bail!(
                "已设置 {ENV_TOKEN} 但缺少 {ENV_BASE_URL}（邮箱 API 基地址是必填项）"
            ),
            (None, None) => Ok(None),
        }
    }

    /// 校验 + 规范化（去掉末尾 `/`）。
    fn validated(base_url: String, token: String, allow_insecure: bool) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let token = token.trim().to_string();
        if base_url.is_empty() {
            bail!("邮箱 API base_url 为空（{ENV_BASE_URL}）");
        }
        if base_url.starts_with("https://") {
            // ok
        } else if base_url.starts_with("http://") {
            if !allow_insecure {
                bail!(
                    "邮箱 API base_url 必须是 https://（当前 {base_url}）；\
                     明文 http 只在显式设置 {ENV_ALLOW_INSECURE}=1 时放行\
                     （仅限可信内网/自建服务）"
                );
            }
            if url_host(&base_url).is_none() {
                bail!("邮箱 API base_url 缺少 host: {base_url}");
            }
            warn_plain_http_once(&base_url);
        } else {
            bail!("邮箱 API base_url 必须带 scheme（https:// 或放行后的 http://）: {base_url}");
        }
        Ok(Self {
            base_url,
            token,
            allow_insecure,
        })
    }

    /// 拼接端点（保证单个 `/`）。
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }

    /// 鉴权头：token 为空时不发（服务端可选鉴权）。
    fn auth_header(&self) -> Option<(String, String)> {
        if self.token.is_empty() {
            None
        } else {
            Some((
                "authorization".to_string(),
                format!("Bearer {}", self.token),
            ))
        }
    }
}

fn is_truthy(raw: Option<&str>) -> bool {
    matches!(
        raw.unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `REG_MAIL_ALLOW_INSECURE` 是否为真（可注入读取器，供单测用）。
pub fn allow_insecure_from_lookup<F>(lookup: &F) -> bool
where
    F: Fn(&str) -> Option<String> + ?Sized,
{
    is_truthy(lookup(ENV_ALLOW_INSECURE).as_deref())
}

/// 从进程环境变量读 `REG_MAIL_ALLOW_INSECURE`。
pub fn allow_insecure_from_env() -> bool {
    allow_insecure_from_lookup(&|key: &str| std::env::var(key).ok())
}

/// 明文 http 告警只打一次（进程级）。返回 `true` 表示这次是首次。
fn warn_plain_http_once(url: &str) -> bool {
    static WARNED: OnceLock<()> = OnceLock::new();
    if WARNED.set(()).is_err() {
        return false;
    }
    let host = url_host(url).unwrap_or_else(|| url.to_string());
    warn!("邮箱取码走明文 http（{host}），仅限可信内网/自建服务");
    true
}

/// URL 的 host 部分（不解析 DNS，只看字面量；丢掉 userinfo / 端口）。
pub fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority); // 丢掉 userinfo
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport.split(':').next().unwrap_or(""),
    };
    let host = host.trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// URL 的主机部分是否是回环地址（不解析 DNS，只看字面量）。
pub fn is_loopback_url(url: &str) -> bool {
    match url_host(url) {
        Some(host) => {
            host == "localhost" || host == "::1" || host == "127.0.0.1" || host.starts_with("127.")
        }
        None => false,
    }
}

// ─────────────────────────── 响应模型 ───────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MailboxResponse {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub code_url: String,
    #[serde(default)]
    pub expires_at: Option<JsonValue>,
}

/// 领到的邮箱。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub email: String,
    pub code_url: String,
    pub expires_at: Option<String>,
}

impl Mailbox {
    pub fn from_response(raw: MailboxResponse, allow_insecure: bool) -> Result<Self> {
        let email = raw.email.trim().to_string();
        let code_url = raw.code_url.trim().to_string();
        if !email.contains('@') {
            bail!("邮箱 API 返回的 email 非法: {email:?}");
        }
        check_fetchable_url("code_url", &code_url, allow_insecure)?;
        Ok(Self {
            email,
            code_url,
            expires_at: raw.expires_at.map(|v| match v {
                JsonValue::String(s) => s,
                other => other.to_string(),
            }),
        })
    }
}

/// 取码页地址必须可安全抓取：`https://`；明文 `http://`（任意 host，含
/// `http://IP:PORT`）只有在 `REG_MAIL_ALLOW_INSECURE=1` 时才放行。
fn check_fetchable_url(field: &str, url: &str, allow_insecure: bool) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") {
        if !allow_insecure {
            bail!(
                "邮箱 API 返回的 {field} 是明文 http://（{url:?}）；必须 https://，\
                 或显式设置 {ENV_ALLOW_INSECURE}=1 才放行明文（仅限可信内网/自建服务）"
            );
        }
        if url_host(url).is_none() {
            bail!("邮箱 API 返回的 {field} 缺少 host: {url:?}");
        }
        warn_plain_http_once(url);
        return Ok(());
    }
    bail!("邮箱 API 返回的 {field} 必须带 scheme（https:// 或放行后的 http://）: {url:?}")
}

/// 解析 `POST /mailboxes` 的响应（201）。
pub fn parse_mailbox_response(status: u16, body: &str, allow_insecure: bool) -> Result<Mailbox> {
    if status != 201 {
        let detail = serde_json::from_str::<JsonValue>(body)
            .ok()
            .and_then(|v| v.get("error").map(|e| e.to_string()))
            .unwrap_or_else(|| body.chars().take(200).collect());
        bail!("创建邮箱失败: HTTP {status}: {detail}");
    }
    let raw: MailboxResponse =
        serde_json::from_str(body).context("邮箱 API 响应不是合法 JSON")?;
    Mailbox::from_response(raw, allow_insecure)
}

/// 解析 `GET /health` 的响应（可选端点）。
pub fn parse_health_response(status: u16, body: &str) -> Result<JsonValue> {
    if !(200..300).contains(&status) {
        bail!("邮箱 API 健康检查失败: HTTP {status}");
    }
    let value: JsonValue =
        serde_json::from_str(body).context("健康检查响应不是合法 JSON")?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        bail!("邮箱 API 健康检查返回异常: {value}");
    }
    Ok(value)
}

// ─────────────────────────── 客户端 ───────────────────────────

/// 通用邮箱 API 客户端。`new_offline` 只用于 dry-run 构造请求计划。
pub struct MailApiClient<'a> {
    http: Option<&'a Client>,
    cfg: EmailApiConfig,
}

impl<'a> MailApiClient<'a> {
    pub fn new(http: &'a Client, cfg: EmailApiConfig) -> Self {
        Self {
            http: Some(http),
            cfg,
        }
    }

    pub fn new_offline(cfg: EmailApiConfig) -> Self {
        Self { http: None, cfg }
    }

    fn http(&self) -> Result<&'a Client> {
        self.http
            .context("MailApiClient 未绑定 HTTP client（offline 模式不能发请求）")
    }

    pub fn config(&self) -> &EmailApiConfig {
        &self.cfg
    }

    pub fn health_spec(&self) -> RequestSpec {
        RequestSpec::get("email.health", self.cfg.endpoint("health")).with_headers(vec![(
            "accept".to_string(),
            "application/json".to_string(),
        )])
    }

    pub fn create_mailbox_spec(
        &self,
        local_part: Option<&str>,
        subdomain: Option<&str>,
    ) -> RequestSpec {
        let mut body = serde_json::Map::new();
        if let Some(local) = local_part.map(str::trim).filter(|s| !s.is_empty()) {
            body.insert("local_part".into(), json!(local));
        }
        if let Some(sub) = subdomain.map(str::trim).filter(|s| !s.is_empty()) {
            body.insert("subdomain".into(), json!(sub));
        }
        let mut headers = vec![("accept".to_string(), "application/json".to_string())];
        if let Some(auth) = self.cfg.auth_header() {
            headers.push(auth);
        }
        RequestSpec::post_json(
            "email.create_mailbox",
            self.cfg.endpoint("mailboxes"),
            Some(headers),
            Some(JsonValue::Object(body)),
        )
    }

    pub fn inbox_spec(&self, code_url: &str) -> RequestSpec {
        inbox_spec(code_url)
    }

    pub async fn health(&self) -> Result<JsonValue> {
        let resp = self.http()?.execute(&self.health_spec()).await?;
        parse_health_response(resp.status, &resp.body)
    }

    pub async fn create_mailbox(
        &self,
        local_part: Option<&str>,
        subdomain: Option<&str>,
    ) -> Result<Mailbox> {
        let resp = self
            .http()?
            .execute(&self.create_mailbox_spec(local_part, subdomain))
            .await?;
        let mailbox = parse_mailbox_response(resp.status, &resp.body, self.cfg.allow_insecure)?;
        info!("[email] 已领取邮箱: {}", mailbox.email);
        Ok(mailbox)
    }

    pub async fn fetch_inbox(&self, code_url: &str) -> Result<String> {
        fetch_inbox_url(self.http()?, code_url).await
    }

    /// 轮询取码：`max_wait_secs` 内每 `interval_secs` 拉一次取码页。
    pub async fn poll_otp(
        &self,
        code_url: &str,
        max_wait_secs: u64,
        interval_secs: u64,
    ) -> Result<String> {
        poll_otp_url(self.http()?, code_url, max_wait_secs, interval_secs).await
    }
}

/// `GET {code_url}`，返回取码页 HTML（静态邮箱池路径也走这里）。
pub async fn fetch_inbox_url(http: &Client, code_url: &str) -> Result<String> {
    let spec = inbox_spec(code_url);
    let resp = http.execute(&spec).await?;
    if !resp.is_success() {
        bail!(
            "取码页返回 HTTP {}: {}",
            resp.status,
            resp.body.chars().take(200).collect::<String>()
        );
    }
    Ok(resp.body)
}

/// 取码页的请求头（与浏览器一致的 no-cache 组合）。
///
/// `accept` 同时接受 JSON 与 HTML：静态池的取码链接可能直接是 JSON API。
pub fn inbox_spec(code_url: &str) -> RequestSpec {
    RequestSpec::get("email.inbox", code_url.to_string()).with_headers(vec![
        (
            "accept".to_string(),
            "application/json, text/html;q=0.9, application/xhtml+xml;q=0.8".to_string(),
        ),
        (
            "cache-control".to_string(),
            "no-cache, no-store, max-age=0".to_string(),
        ),
        ("pragma".to_string(), "no-cache".to_string()),
    ])
}

/// 轮询取码（自由函数版）：静态邮箱池没有 `EmailApiConfig`，但仍要按同一个
/// HTML 卡片 / JSON 逻辑取码，所以把轮询从客户端里摘出来。
///
/// 这类"拉一次返回当前状态"的取码接口（`{"code":"no_code",...}`）**首次请求前
/// 不 sleep**：先立刻拉一次，没有码才按 `interval_secs` 继续轮询。
pub async fn poll_otp_url(
    http: &Client,
    code_url: &str,
    max_wait_secs: u64,
    interval_secs: u64,
) -> Result<String> {
    let started = now_ts();
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);
    let interval = Duration::from_secs(interval_secs.max(1));
    let mut baseline: Option<HashSet<String>> = None;
    let mut last_error = String::from("尚未出现本次请求之后的新验证码");
    let mut attempts = 0usize;

    info!(
        "[email] 开始轮询验证码：最长 {}s，间隔 {}s，取码地址 {}",
        max_wait_secs,
        interval.as_secs(),
        code_url.split('?').next().unwrap_or(code_url)
    );
    loop {
        if Instant::now() >= deadline {
            break;
        }
        attempts += 1;
        match fetch_inbox_url(http, code_url).await {
            Ok(body) => {
                let empty = HashSet::new();
                // ① JSON 取码页优先：固定邮箱服务（`email----code_url`）常把取码链接
                //    做成 `{"code":"123456"}` / `{"code":"no_code","success":false}` 的
                //    JSON API；后者是"还没有码"，继续轮询而不是报错退出。
                if let Some(code) = otp::select_code_from_json(
                    &body,
                    Some(started),
                    baseline.as_ref().unwrap_or(&empty),
                ) {
                    info!(
                        "[email] 第 {attempts} 次取码：已取得验证码（来源 JSON 片段：{}）",
                        snippet(&body)
                    );
                    return Ok(code);
                }
                if let Some(reason) = otp::json_pending_reason(&body) {
                    info!(
                        "[email] 第 {attempts} 次取码：还没有验证码（{reason}，JSON 片段：{}）",
                        snippet(&body)
                    );
                }
                // ② 退回 HTML 卡片解析（原有逻辑不变）
                if baseline.is_none() {
                    baseline = Some(
                        otp::parse_cards(&body)
                            .into_iter()
                            .filter(|card| otp::card_timestamp(card).is_none())
                            .filter_map(|card| card.otp())
                            .collect(),
                    );
                }
                if let Some(code) = otp::select_fresh_otp(
                    &body,
                    Some(started),
                    baseline.as_ref().unwrap_or(&empty),
                ) {
                    info!("[email] 第 {attempts} 次取码：已取得验证码（HTML 卡片）");
                    return Ok(code);
                }
            }
            Err(err) => {
                last_error = format!("{err:#}");
                warn!("[email] 第 {attempts} 次取码失败: {last_error}");
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(interval.min(remaining)).await;
    }
    bail!("等待邮箱验证码超时（共请求 {attempts} 次）: {last_error}")
}

/// 日志用正文片段：压掉换行、截断到 300 字符。
fn snippet(body: &str) -> String {
    let flat: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut out: String = flat.chars().take(300).collect();
    if flat.chars().count() > 300 {
        out.push('…');
    }
    out
}

// ─────────────────────── 静态邮箱池（固定邮箱 + 取码链接）───────────────────────

/// 「固定邮箱 + 取码链接」清单：**只支持** `email----code_url` 这一种行格式。
///
/// 这类邮箱是**用户提前买好/生成好**的，服务端没有 `POST /mailboxes` 接口，
/// 所以走"静态池"模式：按顺序取一行，取码仍走 `GET {code_url}`（JSON / HTML 都认）。
///
/// * 已用过的邮箱追加进 `<email-file>.used`（每行一个 email），下次启动自动跳过，
///   否则重跑一遍会拿同一个邮箱注册、撞 `409 user_exists`。`.used` 按**文件路径**
///   区分（`<清单路径>.used`），多个清单互不污染。
/// * 格式不对的行**明确报错并跳过**（打印行号 + 原因），不静默忽略、也不整批中止。
/// * `code_url` 允许 `http://IP:PORT/...?query`，但仅当 `REG_MAIL_ALLOW_INSECURE=1`；
///   未开启时明文 http 行按"格式不对"处理（默认安全）。
/// * 并发安全：进程内用互斥锁串行化，进程间用 `<email-file>.lock` 文件锁
///   （`OpenOptions::create_new` 原子创建）保证**同一行不会被两个任务同时取走**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticEmailPool {
    path: PathBuf,
    /// `REG_MAIL_ALLOW_INSECURE=1`：放行任意 host 的明文 `http://` code_url。
    allow_insecure: bool,
}

impl StaticEmailPool {
    /// 默认**不放行**明文 http（与历史行为一致）。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            allow_insecure: false,
        }
    }

    /// 显式指定是否放行明文 http（`REG_MAIL_ALLOW_INSECURE`）。
    pub fn new_with_insecure(path: impl Into<PathBuf>, allow_insecure: bool) -> Self {
        Self {
            path: path.into(),
            allow_insecure,
        }
    }

    pub fn allow_insecure(&self) -> bool {
        self.allow_insecure
    }

    /// 从可注入读取器解析 `REG_MAIL_EMAIL_FILE`；未设置返回 `None`。
    /// 同时读取 `REG_MAIL_ALLOW_INSECURE`。
    pub fn from_lookup<F>(lookup: &F) -> Option<Self>
    where
        F: Fn(&str) -> Option<String> + ?Sized,
    {
        let path = lookup(ENV_EMAIL_FILE)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;
        Some(Self::new_with_insecure(
            path,
            allow_insecure_from_lookup(lookup),
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `<email-file>.used`（追加 email，一行一个）。
    pub fn used_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".used");
        PathBuf::from(p)
    }

    /// `<email-file>.lock`（跨进程互斥的锁文件）。
    pub fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".lock");
        PathBuf::from(p)
    }

    /// 取下一行未用过的邮箱（线程安全 + 跨进程安全）。
    ///
    /// 返回的 [`Mailbox`] 里 `expires_at = None`，`code_url` 原样来自文件。
    pub fn next(&self) -> Result<Mailbox> {
        // 进程内先串行化：走同一文件的两个并发任务不能同时读 used。
        static POOL_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = POOL_GUARD.lock().unwrap_or_else(|e| e.into_inner());

        let _lock = FileLock::acquire(&self.lock_path())?;

        let text = self.read_pool_text()?;
        let used = self.read_used();
        let mut total = 0usize;
        let mut skipped = 0usize;
        for (lineno, line) in text.lines().enumerate() {
            let parsed = match parse_static_email_line_with(line, self.allow_insecure) {
                Ok(v) => v,
                Err(err) => {
                    skipped += 1;
                    warn!(
                        "[email] 静态池第 {} 行格式不对，已跳过：{err:#}",
                        lineno + 1
                    );
                    continue;
                }
            };
            let Some(mailbox) = parsed else {
                continue;
            };
            total += 1;
            if used.contains(&mailbox.email.to_ascii_lowercase()) {
                continue;
            }
            self.append_used(&mailbox.email)?;
            info!(
                "[email] 静态池取用第 {} 个邮箱（已用 {} 个，跳过 {} 行）: {}",
                total,
                used.len() + 1,
                skipped,
                mailbox.email
            );
            return Ok(mailbox);
        }
        bail!(
            "静态邮箱池已用尽：{}（共 {} 个有效邮箱，跳过 {} 行，used 文件 {}）",
            self.path.display(),
            total,
            skipped,
            self.used_path().display()
        )
    }

    /// **只解析不取用**：不写 `.used`、不创建锁文件，供 `email-pool` 子命令自检。
    pub fn scan(&self) -> Result<PoolScan> {
        let text = self.read_pool_text()?;
        let used = self.read_used();
        let mut scan = PoolScan {
            path: self.path.clone(),
            file_lines: text.lines().count(),
            ..Default::default()
        };
        for (lineno, line) in text.lines().enumerate() {
            match parse_static_email_line_with(line, self.allow_insecure) {
                Ok(None) => {}
                Ok(Some(mailbox)) => {
                    if used.contains(&mailbox.email.to_ascii_lowercase()) {
                        scan.used_entries += 1;
                    }
                    scan.entries.push(mailbox);
                }
                Err(err) => scan
                    .skipped
                    .push((lineno + 1, format!("{err:#}"))),
            }
        }
        Ok(scan)
    }

    fn read_pool_text(&self) -> Result<String> {
        let text = fs::read_to_string(&self.path).with_context(|| {
            format!(
                "读取静态邮箱池失败: {}（每行格式 email{}code_url）",
                self.path.display(),
                STATIC_EMAIL_SEPARATOR
            )
        })?;
        // Windows 记事本 / Excel 导出的清单常带 UTF-8 BOM：留在第一行的 email 里
        // 会变成一个非法字符（`\ufeffxxx@…`），注册时邮箱直接错。
        Ok(match text.strip_prefix('\u{feff}') {
            Some(rest) => rest.to_string(),
            None => text,
        })
    }

    fn read_used(&self) -> HashSet<String> {
        let path = self.used_path();
        let Ok(text) = fs::read_to_string(&path) else {
            return HashSet::new();
        };
        text.lines()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|l| !l.is_empty())
            .collect()
    }

    fn append_used(&self, email: &str) -> Result<()> {
        let path = self.used_path();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("写 used 文件失败: {}", path.display()))?;
        writeln!(file, "{email}").with_context(|| format!("写 used 文件失败: {}", path.display()))?;
        Ok(())
    }
}

/// 静态池**只解析不取用**的结果（`email-pool` 子命令 / 单测用）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolScan {
    pub path: PathBuf,
    /// 文件总行数（含空行 / 注释行）。
    pub file_lines: usize,
    /// 解析成功的条目（按文件顺序）。
    pub entries: Vec<Mailbox>,
    /// 格式不对的行：`(1 起的行号, 原因)`。
    pub skipped: Vec<(usize, String)>,
    /// 解析成功但已在 `.used` 里的条目数。
    pub used_entries: usize,
}

impl PoolScan {
    /// 跳过行数。
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }
}

/// 解析静态池一行：`email----code_url`（唯一受支持格式）。
///
/// 空行 / `#` 注释行返回 `Ok(None)`；格式不对返回错误（带行号由调用方补）。
/// 等价于 `allow_insecure = false`（明文 http 一律拒绝）。
pub fn parse_static_email_line(line: &str) -> Result<Option<Mailbox>> {
    parse_static_email_line_with(line, false)
}

/// 解析静态池一行，`allow_insecure` = `REG_MAIL_ALLOW_INSECURE`。
///
/// * 空行 / `#` 注释行 → `Ok(None)`
/// * 缺少 `----` / email 非法 / code_url 无 scheme → `Err`（调用方按行号告警并跳过）
/// * `http://` → 仅 `allow_insecure` 时放行（并打印一次明文告警），否则 `Err`
pub fn parse_static_email_line_with(line: &str, allow_insecure: bool) -> Result<Option<Mailbox>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    let Some((email, code_url)) = trimmed.split_once(STATIC_EMAIL_SEPARATOR) else {
        bail!("缺少分隔符 {STATIC_EMAIL_SEPARATOR:?}（期望 email{STATIC_EMAIL_SEPARATOR}code_url）: {trimmed:?}");
    };
    let email = email.trim().trim_start_matches('\u{feff}').trim().to_string();
    let code_url = code_url.trim().trim_start_matches('\u{feff}').trim().to_string();
    if email.is_empty() {
        bail!("email 为空: {trimmed:?}");
    }
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        bail!("email 非法（需要 local@domain）: {email:?}");
    }
    if email.chars().any(|c| c.is_whitespace()) {
        bail!("email 含空白字符: {email:?}");
    }
    if code_url.is_empty() {
        bail!("code_url 为空: {trimmed:?}");
    }
    if code_url.chars().any(|c| c.is_whitespace()) {
        bail!("code_url 含空白字符: {code_url:?}");
    }
    if code_url.starts_with("https://") {
        // ok
    } else if code_url.starts_with("http://") {
        if !allow_insecure {
            bail!(
                "code_url 是明文 http://（{code_url}）；必须 https://，或显式设置 \
                 {ENV_ALLOW_INSECURE}=1 才放行明文（仅限可信内网/自建服务）"
            );
        }
        warn_plain_http_once(&code_url);
    } else {
        bail!("code_url 必须带 scheme（https:// 或放行后的 http://）: {code_url:?}");
    }
    if url_host(&code_url).is_none() {
        bail!("code_url 缺少 host: {code_url:?}");
    }
    Ok(Some(Mailbox {
        email,
        code_url,
        expires_at: None,
    }))
}

/// `<path>.lock` 的跨进程互斥（`create_new` 原子创建，Drop 时删除）。
struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut cleared = false;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        if cleared {
                            bail!(
                                "拿不到邮箱池文件锁（超时）：{}（若确认没有其它进程在用，删掉它重试）",
                                path.display()
                            );
                        }
                        // 陈旧锁（上次进程被强杀）：清一次再试
                        let _ = fs::remove_file(path);
                        cleared = true;
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(err) => {
                    return Err(err).with_context(|| format!("创建文件锁失败: {}", path.display()))
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
