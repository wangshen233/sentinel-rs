//! auth.openai.com 侧：请求构造 + 响应解析（纯数据，离线可测）。
//!
//! 行为对齐 Python `协议/auth_flow.py`：
//!   * `authorize_continue()`      → `POST /api/accounts/authorize/continue`
//!   * `register_password()`       → `POST /api/accounts/user/register`
//!   * `send_otp()` / `resend_otp()` → `GET /api/accounts/email-otp/send`、`POST .../resend`
//!   * `verify_otp()`              → `POST /api/accounts/email-otp/validate`
//!   * `create_account()`          → `POST /api/accounts/create_account`
//!
//! 每个函数只返回 [`RequestSpec`]，真正发送在 [`super::http`]。

use super::http::{RequestSpec, DEFAULT_TIMEOUT_SECS};
use super::SentinelToken;
use crate::fingerprint::DeviceFingerprint;
use anyhow::{bail, Context, Result};
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use std::sync::Mutex;

pub const AUTH_BASE: &str = "https://auth.openai.com";
pub const CHATGPT_BASE: &str = "https://chatgpt.com";

/// chatgpt.com 的 CSRF 端点（同时是 warmup：GET 它就会种下 `oai-did`）。
pub const EP_CHATGPT_CSRF: &str = "https://chatgpt.com/api/auth/csrf";
/// NextAuth 的 openai signin 端点：POST 它才拿到带 `login_hint` 的 authorize URL。
pub const EP_CHATGPT_SIGNIN: &str = "https://chatgpt.com/api/auth/signin/openai";
/// signin 的 Referer（对齐 Python `get_auth_url`）。
pub const REFERER_CHATGPT_LOGIN: &str = "https://chatgpt.com/auth/login";

/// authorize URL 的 `ccaps` 参数（2026-09-21 真机抓包原句，Python `_CC_CAPS`）。
pub const CC_CAPS: &str = "login_methods chatgpt_login_finalizer_v1";
/// authorize URL 的 `auth_return_target_category`（Python `_AUTH_RETURN_TARGET_CATEGORY`）。
pub const AUTH_RETURN_TARGET_CATEGORY: &str = "chatgpt_home";

pub const EP_AUTHORIZE_CONTINUE: &str = "https://auth.openai.com/api/accounts/authorize/continue";
pub const EP_USER_REGISTER: &str = "https://auth.openai.com/api/accounts/user/register";
pub const EP_OTP_SEND: &str = "https://auth.openai.com/api/accounts/email-otp/send";
pub const EP_OTP_RESEND: &str = "https://auth.openai.com/api/accounts/email-otp/resend";
pub const EP_OTP_VALIDATE: &str = "https://auth.openai.com/api/accounts/email-otp/validate";
pub const EP_CREATE_ACCOUNT: &str = "https://auth.openai.com/api/accounts/create_account";
/// 已有账号登录：密码校验（对齐 Python `login_password_verify`）。
pub const EP_PASSWORD_VERIFY: &str = "https://auth.openai.com/api/accounts/password/verify";
/// 已有账号登录：TOTP 2FA 校验（对齐 Python `submit_mfa_totp`）。
pub const EP_MFA_VERIFY: &str = "https://auth.openai.com/api/accounts/mfa/verify";
/// OAuth 授权码换 token（表单 POST）。
pub const EP_OAUTH_TOKEN: &str = "https://auth.openai.com/oauth/token";
/// workspace 选择（create_account 返回 `/workspace` 页面时调用）。
pub const EP_WORKSPACE_SELECT: &str = "https://auth.openai.com/api/accounts/workspace/select";
/// chatgpt.com 的会话端点（`accessToken` / `sessionToken` 的最终来源）。
pub const EP_CHAT_SESSION: &str = "https://chatgpt.com/api/auth/session";
/// callback 路径（NextAuth）。
pub const CALLBACK_PATH: &str = "/api/auth/callback/openai";
/// chatgpt 主页 Referer。
pub const CHATGPT_BASE_REFERER: &str = "https://chatgpt.com/";
/// workspace/select 与 oauth/token 的 Referer（对齐 Python）。
pub const REFERER_CODEX_CONSENT: &str = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent";
/// OAuth `redirect_uri` 默认值（对齐 Python `_oauth_redirect_uri`）。
pub const DEFAULT_REDIRECT_URI: &str = "https://chatgpt.com/api/auth/callback/openai";
/// OAuth `client_id` 占位（Python 侧同样回退到 `YOUR_OPENAI_WEB_CLIENT_ID`）。
pub const DEFAULT_OAUTH_CLIENT_ID: &str = "YOUR_OPENAI_WEB_CLIENT_ID";

pub const PAGE_CREATE_ACCOUNT_PASSWORD: &str = "https://auth.openai.com/create-account/password";
pub const PAGE_EMAIL_VERIFICATION: &str = "https://auth.openai.com/email-verification";
pub const PAGE_ABOUT_YOU: &str = "https://auth.openai.com/about-you";
pub const PAGE_CREATE_ACCOUNT: &str = "https://auth.openai.com/create-account";
/// 已有账号登录的入口页（`authorize/continue` 的 Referer，Python 原句）。
pub const PAGE_LOG_IN: &str = "https://auth.openai.com/log-in";
/// 已有账号登录的密码页（`password/verify` 的 Referer）。
pub const PAGE_LOG_IN_PASSWORD: &str = "https://auth.openai.com/log-in/password";
/// mfa-challenge 页（`mfa/verify` 的 Referer）。
pub const PAGE_MFA_CHALLENGE: &str = "https://auth.openai.com/mfa-challenge";
/// signin 的 `screen_hint`（登录链路口径，Python `run_protocol_login` 用 `login`）。
pub const SCREEN_HINT_LOGIN: &str = "login";

/// sentinel 主 token 头。
pub const HDR_SENTINEL: &str = "openai-sentinel-token";
/// sentinel SO token 头（`email_otp_validate` / `create_account` 服务端要求）。
pub const HDR_SENTINEL_SO: &str = "openai-sentinel-so-token";
/// 每次整页文档导航换一个；同一文档内的多个 POST 共用。
pub const HDR_NAVIGATION_ID: &str = "x-openai-document-navigation-id";
/// 每次调用一个全新的 uuid4。
pub const HDR_INVOCATION_ID: &str = "x-access-flow-invocation-id";
/// 设备 id（对齐 Python `oai-device-id`）。
pub const HDR_DEVICE_ID: &str = "oai-device-id";

// ─────────────────────────── 请求构造 ───────────────────────────

/// Chrome 的低熵 client hints（对齐 Python `_format_brand_list(full=False)`）。
///
/// 真机抓包：`"Chromium";v="145", "Not?A_Brand";v="24", "Google Chrome";v="145"`。
/// 只有 Chromium 家族才发这三个头；Safari / Firefox 一个都不发（Python 侧
/// `if fp.get("sec_ch_ua")` 守卫）。UA 与 platform 头必须同族，否则比不发更假。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHints {
    pub sec_ch_ua: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
}

impl ClientHints {
    /// 从 UA 推 CH（**只在显式指定 UA、没有设备指纹时**用）。
    ///
    /// 非 Chromium 家族 / 非 Windows 或 macOS 返回 `None`。平台必须从 UA 里认出来：
    /// 早期实现只认 `Windows NT`，macOS 的 Chrome UA 会一个 CH 头都不发——比发错更假。
    pub fn from_user_agent(user_agent: &str) -> Option<Self> {
        if !user_agent.contains("Chrome/") || user_agent.contains("Firefox/") {
            return None;
        }
        let platform = if user_agent.contains("Windows NT") {
            "\"Windows\""
        } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS X") {
            "\"macOS\""
        } else {
            return None;
        };
        let marker = "Chrome/";
        let start = user_agent.find(marker)? + marker.len();
        let major: String = user_agent[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if major.is_empty() {
            return None;
        }
        Some(Self {
            sec_ch_ua: format!(
                "\"Chromium\";v=\"{major}\", \"Not?A_Brand\";v=\"24\", \
                 \"Google Chrome\";v=\"{major}\""
            ),
            sec_ch_ua_mobile: "?0".to_string(),
            sec_ch_ua_platform: platform.to_string(),
        })
    }

    /// 直接用设备指纹里的三元组（版本 / 平台与 UA 同源，不会对不上）。
    pub fn from_fingerprint(fp: &DeviceFingerprint) -> Self {
        Self {
            sec_ch_ua: fp.sec_ch_ua.clone(),
            sec_ch_ua_mobile: fp.sec_ch_ua_mobile.clone(),
            sec_ch_ua_platform: fp.sec_ch_ua_platform.clone(),
        }
    }

    /// 写进请求头的三元组（顺序对齐 Python：ua / mobile / platform）。
    fn header_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("sec-ch-ua".to_string(), self.sec_ch_ua.clone()),
            ("sec-ch-ua-mobile".to_string(), self.sec_ch_ua_mobile.clone()),
            (
                "sec-ch-ua-platform".to_string(),
                self.sec_ch_ua_platform.clone(),
            ),
        ]
    }
}

/// 文档导航的 `sec-fetch-site` 取值（对齐 Python `_navigation_headers` 的三处用法）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSite {
    /// 地址栏直达（chatgpt.com warmup）：`none` + `sec-fetch-user: ?1`。
    None,
    /// 同源页面内跳转（auth.create-account → create-account/password）。
    SameOrigin,
    /// chatgpt.com → auth.openai.com 的 OAuth 跳转（302 自动跟随不是用户点击）。
    CrossSite,
}

impl FetchSite {
    fn as_str(self) -> &'static str {
        match self {
            FetchSite::None => "none",
            FetchSite::SameOrigin => "same-origin",
            FetchSite::CrossSite => "cross-site",
        }
    }
}

/// Datadog RUM 追踪头（对齐 Python `_datadog_trace_headers`）。
///
/// 真机三处 auth JSON POST 都带；`tracestate` 固定 `dd=s:1;o=rum`，
/// 且**不发** `x-datadog-tags`（旧实现多发的那一个正是字节级指纹差异）。
pub fn datadog_trace_headers() -> Vec<(String, String)> {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let trace_id: u64 = rng.gen();
    let span_id: u64 = rng.gen();
    let session: u64 = rng.gen::<u64>() >> 1;
    let parent: u64 = rng.gen::<u64>() >> 1;
    vec![
        (
            "traceparent".to_string(),
            format!("00-0000000000000000{trace_id:016x}-{span_id:016x}-01"),
        ),
        ("tracestate".to_string(), "dd=s:1;o=rum".to_string()),
        ("x-datadog-trace-id".to_string(), session.to_string()),
        ("x-datadog-parent-id".to_string(), parent.to_string()),
        ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ("x-datadog-origin".to_string(), "rum".to_string()),
    ]
}

/// 构造 auth 侧请求：持有 UA / 语言 / 设备 id / 当前文档 navigation id。
///
/// `navigation_id` 用 `Mutex` 包着，因为 Python 侧是"文档导航时铸新值，
/// 同文档内多个 POST 共用"，而调用方（编排层）拿的是 `&self`。
pub struct AuthRequestBuilder {
    user_agent: String,
    accept_language: String,
    device_id: String,
    navigation_id: Mutex<String>,
    /// client hints（Chrome 指纹才有值；Safari/Firefox 为 `None`，一个都不发）。
    hints: Option<ClientHints>,
    /// 贯穿 signin → authorize 的 `auth_session_logging_id`（Python 侧同名字段）。
    auth_session_logging_id: String,
}

impl AuthRequestBuilder {
    pub fn new(user_agent: &str, accept_language: &str, device_id: &str) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            accept_language: accept_language.to_string(),
            device_id: device_id.to_string(),
            navigation_id: Mutex::new(new_uuid()),
            hints: ClientHints::from_user_agent(user_agent),
            auth_session_logging_id: new_uuid(),
        }
    }

    /// 用设备指纹覆盖 UA / 语言 / client hints（三者同源，永远一致）。
    ///
    /// 没有指纹（显式指定 UA 的旧路径）时调用方不该调这个方法，构造器里的
    /// [`ClientHints::from_user_agent`] 已经能从 UA 推出对应平台。
    pub fn with_fingerprint(mut self, fp: &DeviceFingerprint) -> Self {
        self.user_agent = fp.user_agent.clone();
        self.accept_language = fp.languages.clone();
        self.hints = Some(ClientHints::from_fingerprint(fp));
        self
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn accept_language(&self) -> &str {
        &self.accept_language
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// client hints（`None` = 该指纹不该发 CH）。
    pub fn client_hints(&self) -> Option<&ClientHints> {
        self.hints.as_ref()
    }

    pub fn auth_session_logging_id(&self) -> &str {
        &self.auth_session_logging_id
    }

    /// 覆盖 `auth_session_logging_id`（多轮复用同一个值时用）。
    pub fn set_auth_session_logging_id(&mut self, value: impl Into<String>) {
        let value = value.into();
        if !value.trim().is_empty() {
            self.auth_session_logging_id = value.trim().to_string();
        }
    }

    pub fn navigation_id(&self) -> String {
        self.navigation_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 铸一个新的 document-navigation-id（整页导航后调用），返回新值。
    pub fn new_document_navigation(&self) -> String {
        let id = new_uuid();
        *self.navigation_id.lock().unwrap_or_else(|e| e.into_inner()) = id.clone();
        id
    }

    /// XHR/JSON 公共头（对齐 `_common_headers` 的关键子集，含 client hints）。
    ///
    /// `with_device_id`：Python 只在 `chatgpt.com/backend-api|backend-anon` 下发
    /// `oai-device-id`，但既有用例（`authorize/continue` 等 auth JSON POST）依赖它
    /// 存在，所以这里保留原行为，只给 signin 这类 chatgpt.com `/api/auth/*` 关掉。
    fn xhr_headers(&self, with_device_id: bool) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = vec![
            ("accept-language".into(), self.accept_language.clone()),
            (
                "accept-encoding".into(),
                "gzip, deflate, br, zstd".to_string(),
            ),
            ("sec-fetch-dest".into(), "empty".into()),
            ("sec-fetch-mode".into(), "cors".into()),
            ("sec-fetch-site".into(), "same-origin".into()),
            ("priority".into(), "u=1, i".into()),
        ];
        if let Some(hints) = &self.hints {
            headers.extend(hints.header_pairs());
        }
        if with_device_id {
            headers.push((HDR_DEVICE_ID.into(), self.device_id.clone()));
        }
        headers.extend(datadog_trace_headers());
        headers
    }

    fn base_headers(&self) -> Vec<(String, String)> {
        self.xhr_headers(true)
    }

    /// JSON POST 头（对齐 `_auth_json_headers`：两个一次性头 + Content-Type）。
    pub fn auth_json_headers(&self, referer: &str) -> Vec<(String, String)> {
        let mut headers = self.base_headers();
        headers.push(("accept".into(), "application/json".into()));
        headers.push(("referer".into(), referer.into()));
        headers.push(("origin".into(), AUTH_BASE.into()));
        headers.push(("content-type".into(), "application/json".into()));
        headers.push((HDR_INVOCATION_ID.into(), new_uuid()));
        headers.push((HDR_NAVIGATION_ID.into(), self.navigation_id()));
        headers
    }

    /// 整页文档导航头（对齐 Python `_navigation_headers`：document/navigate）。
    ///
    /// 默认形态 = 同源页面内跳转（`same-origin` + `sec-fetch-user`），对应 Python
    /// `register_password` 里打开 `create-account/password` 那一次导航。
    pub fn navigation_headers(&self, referer: &str) -> Vec<(String, String)> {
        self.navigation_headers_for(referer, FetchSite::SameOrigin, true)
    }

    /// 整页文档导航头（可指定 `sec-fetch-site` / 是否发 `sec-fetch-user`）。
    ///
    /// Python `_navigation_headers()` 的完整形态：accept + 语言 + 编码 +
    /// sec-fetch-dest/mode/site(/user) + upgrade-insecure-requests + priority +
    /// **client hints 全套**。`auth_oauth_init` 额外把 site 改成 `cross-site`
    /// 并摘掉 `sec-fetch-user`（302 自动跟随不是用户手动点击）。
    pub fn navigation_headers_for(
        &self,
        referer: &str,
        site: FetchSite,
        include_user: bool,
    ) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = vec![
            (
                "accept".into(),
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\
                 image/apng,*/*;q=0.8"
                    .into(),
            ),
            ("accept-language".into(), self.accept_language.clone()),
            (
                "accept-encoding".into(),
                "gzip, deflate, br, zstd".to_string(),
            ),
            ("referer".into(), referer.into()),
            ("sec-fetch-dest".into(), "document".into()),
            ("sec-fetch-mode".into(), "navigate".into()),
            ("sec-fetch-site".into(), site.as_str().into()),
        ];
        if include_user {
            headers.push(("sec-fetch-user".into(), "?1".into()));
        }
        headers.push(("upgrade-insecure-requests".into(), "1".into()));
        headers.push(("priority".into(), "u=0, i".into()));
        if let Some(hints) = &self.hints {
            headers.extend(hints.header_pairs());
        }
        headers.extend(datadog_trace_headers());
        headers
    }

    /// `GET https://chatgpt.com/api/auth/csrf` —— warmup：种 `oai-did` + 拿 csrfToken。
    ///
    /// Python `warmup()` 的等价物（地址栏直达 → `sec-fetch-site: none`）。
    /// 这条 cookie 是后面 authorize 会话能否建立的前提：没有它 signin 会返回
    /// NextAuth 页而不是 auth.openai.com 的 authorize URL，后续必 409。
    pub fn warmup_spec(&self) -> RequestSpec {
        RequestSpec::get("chatgpt.warmup", EP_CHATGPT_CSRF).with_headers(
            self.navigation_headers_for(CHATGPT_BASE_REFERER, FetchSite::None, true),
        )
    }

    /// `POST https://chatgpt.com/api/auth/signin/openai?...` —— 换 authorize URL。
    ///
    /// 对齐 Python `get_auth_url`：
    ///   query : prompt=login & ext-oai-did & auth_session_logging_id
    ///           & screen_hint=login_or_signup & login_hint=<email>
    ///   body  : callbackUrl=%2F & csrfToken & json=true
    ///   头    : accept/referer/UA/CH 全套，**没有** Origin（同源）。
    pub fn signin_openai_spec(
        &self,
        email: &str,
        csrf_token: &str,
        device_id: &str,
        auth_session_logging_id: &str,
    ) -> RequestSpec {
        let mut query = vec![
            ("prompt", "login".to_string()),
            ("ext-oai-did", device_id.to_string()),
            (
                "auth_session_logging_id",
                auth_session_logging_id.to_string(),
            ),
            ("screen_hint", "login_or_signup".to_string()),
        ];
        if !email.trim().is_empty() {
            query.push(("login_hint", email.trim().to_string()));
        }
        let query_text = query
            .iter()
            .map(|(key, value)| format!("{}={}", urlencode(key), urlencode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{EP_CHATGPT_SIGNIN}?{query_text}");

        let mut headers = self.xhr_headers(false);
        headers.push(("accept".into(), "application/json".into()));
        headers.push(("referer".into(), REFERER_CHATGPT_LOGIN.into()));
        let form = format!(
            "callbackUrl={}&csrfToken={}&json=true",
            urlencode("/"),
            urlencode(csrf_token)
        );
        RequestSpec::post_form("chatgpt.signin_openai", url, Some(headers), form)
    }

    /// `GET <authorize URL>` —— OAuth 初始化：跟随 authorize 链、落会话状态。
    ///
    /// 对齐 Python `auth_oauth_init` 的头：整页导航 + `sec-fetch-site: cross-site`，
    /// **不发** `sec-fetch-user`。这一步建立的就是后续 `user/register` 要用的 state。
    pub fn authorize_init_spec(&self, authorize_url: &str) -> RequestSpec {
        RequestSpec {
            label: "auth.authorize_init",
            method: super::http::Method::Get,
            url: authorize_url.to_string(),
            headers: self.navigation_headers_for(
                CHATGPT_BASE_REFERER,
                FetchSite::CrossSite,
                false,
            ),
            body: None,
            raw_body: None,
        }
    }

    /// `GET https://auth.openai.com/create-account/password` —— 建立"设密码"页状态。
    ///
    /// 对齐 Python `register_password` 开头那次文档导航（同源、带 sec-fetch-user），
    /// 之后要立刻 [`Self::new_document_navigation`] 铸新 id 给 `user/register`。
    pub fn create_account_password_page(&self) -> RequestSpec {
        self.navigation_from(PAGE_CREATE_ACCOUNT_PASSWORD, PAGE_CREATE_ACCOUNT)
    }

    fn sentinel_headers(&self, st: &SentinelToken) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if !st.token.is_empty() {
            headers.push((HDR_SENTINEL.into(), st.token.clone()));
        }
        if let Some(so) = &st.so_token {
            if !so.is_empty() {
                headers.push((HDR_SENTINEL_SO.into(), so.clone()));
            }
        }
        headers
    }

    /// `POST /api/accounts/authorize/continue`
    pub fn authorize_continue(
        &self,
        email: &str,
        sentinel_token: &str,
        screen_hint: &str,
    ) -> RequestSpec {
        self.authorize_continue_with(email, sentinel_token, screen_hint, PAGE_CREATE_ACCOUNT)
    }

    /// 同 [`Self::authorize_continue`]，但显式指定 Referer。
    ///
    /// 登录链路（Python `run_protocol_login`）用的是
    /// `screen_hint="login"` + `referer=https://auth.openai.com/log-in`；
    /// 注册/探测链路才是 `create-account`。Referer 决定页面状态机判定，必须分开。
    pub fn authorize_continue_with(
        &self,
        email: &str,
        sentinel_token: &str,
        screen_hint: &str,
        referer: &str,
    ) -> RequestSpec {
        let mut headers = self.auth_json_headers(referer);
        if !sentinel_token.is_empty() {
            headers.push((HDR_SENTINEL.into(), sentinel_token.to_string()));
        }
        RequestSpec::post_json(
            "auth.authorize_continue",
            EP_AUTHORIZE_CONTINUE,
            Some(headers),
            Some(json!({
                "username": { "value": email, "kind": "email" },
                "screen_hint": screen_hint,
            })),
        )
    }

    /// `GET https://auth.openai.com/log-in/password` —— 打开"输入密码"页（整页导航）。
    ///
    /// Python `run_protocol_login` 里没有这一步（它直接 POST `password/verify`），
    /// 这里只作**兜底**：`password/verify` 返回 409 `invalid_state`（说明会话里没有
    /// 密码页状态的记录）时补一次导航再重试一次，避免整轮白跑。
    pub fn login_password_page(&self) -> RequestSpec {
        self.navigation_from(PAGE_LOG_IN_PASSWORD, PAGE_LOG_IN)
    }

    /// `POST /api/accounts/password/verify` —— 已有账号密码登录。
    ///
    /// 头按 Python `login_password_verify` 构造：`_common_headers`（**不是**
    /// `_auth_json_headers`，所以没有两个 `x-*` 一次性头）+ `Content-Type`
    /// + sentinel 头（Python 复用上一次的 `_last_sentinel_token`）。
    pub fn login_password_verify(&self, password: &str, st: &SentinelToken) -> RequestSpec {
        let mut headers = self.common_json_headers(PAGE_LOG_IN_PASSWORD);
        headers.push(("content-type".into(), "application/json".into()));
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json(
            "auth.password_verify",
            EP_PASSWORD_VERIFY,
            Some(headers),
            Some(json!({ "password": password })),
        )
    }

    /// `POST /api/accounts/mfa/verify` —— 提交 TOTP 动态码（已有账号 2FA）。
    ///
    /// body 对齐 Python `submit_mfa_totp`：`{"code","type":"totp","id":<challenge_id>}`。
    pub fn mfa_verify(&self, code: &str, challenge_id: &str, st: &SentinelToken) -> RequestSpec {
        let mut headers = self.common_json_headers(PAGE_MFA_CHALLENGE);
        headers.push(("content-type".into(), "application/json".into()));
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json(
            "auth.mfa_verify",
            EP_MFA_VERIFY,
            Some(headers),
            Some(json!({ "code": code, "type": "totp", "id": challenge_id })),
        )
    }

    /// 整页导航到某个 auth 页面（纯协议用它等价建立页面状态）。
    pub fn navigation(&self, url: &str) -> RequestSpec {
        self.navigation_from(url, PAGE_CREATE_ACCOUNT)
    }

    /// 整页导航，显式指定 Referer（跟随 302 链时用：referer 是上一跳）。
    pub fn navigation_from(&self, url: &str, referer: &str) -> RequestSpec {
        let headers = self.navigation_headers(referer);
        RequestSpec {
            label: "auth.navigation",
            method: super::http::Method::Get,
            url: url.to_string(),
            headers,
            body: None,
            raw_body: None,
        }
    }

    /// `POST /api/accounts/user/register` —— 设密码（服务端账号在这一步建立）。
    ///
    /// 该 flow（`username_password_create`）服务端一般不下发 so 块，所以 SO 头缺失是正常的。
    pub fn register_password(
        &self,
        email: &str,
        password: &str,
        st: &SentinelToken,
    ) -> RequestSpec {
        let mut headers = self.auth_json_headers(PAGE_CREATE_ACCOUNT_PASSWORD);
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json(
            "auth.user_register",
            EP_USER_REGISTER,
            Some(headers),
            Some(json!({ "password": password, "username": email })),
        )
    }

    /// `GET /api/accounts/email-otp/send` —— 新注册流程的发码（对齐 Python 的 GET）。
    ///
    /// 头走 `_common_headers`（不是 `_auth_json_headers`）：真机这一步是整页文档
    /// 导航，不带 `content-type`、两个 `x-*` 一次性头也不下发。
    pub fn send_otp(&self, st: &SentinelToken) -> RequestSpec {
        let mut headers = self.common_json_headers(PAGE_CREATE_ACCOUNT_PASSWORD);
        headers.extend(self.sentinel_headers(st));
        RequestSpec {
            label: "auth.email_otp_send",
            method: super::http::Method::Get,
            url: EP_OTP_SEND.to_string(),
            headers,
            body: None,
            raw_body: None,
        }
    }

    /// `POST /api/accounts/email-otp/resend` —— 已有账号 / 重发。
    pub fn resend_otp(&self, st: &SentinelToken) -> RequestSpec {
        let mut headers = self.auth_json_headers(PAGE_EMAIL_VERIFICATION);
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json("auth.email_otp_resend", EP_OTP_RESEND, Some(headers), None)
    }

    /// `POST /api/accounts/email-otp/validate` —— 提交邮箱验证码。
    pub fn verify_otp(&self, code: &str, st: &SentinelToken) -> RequestSpec {
        let mut headers = self.auth_json_headers(PAGE_EMAIL_VERIFICATION);
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json(
            "auth.email_otp_validate",
            EP_OTP_VALIDATE,
            Some(headers),
            Some(json!({ "code": code })),
        )
    }

    /// `POST /api/accounts/create_account` —— 提交姓名/生日。
    pub fn create_account(&self, st: &SentinelToken) -> RequestSpec {
        self.create_account_with(&random_name(), &random_birthdate(), st)
    }

    /// 指定姓名/生日（测试用，避免随机值影响断言）。
    pub fn create_account_with(
        &self,
        name: &str,
        birthdate: &str,
        st: &SentinelToken,
    ) -> RequestSpec {
        let mut headers = self.auth_json_headers(PAGE_ABOUT_YOU);
        headers.extend(self.sentinel_headers(st));
        RequestSpec::post_json(
            "auth.create_account",
            EP_CREATE_ACCOUNT,
            Some(headers),
            Some(json!({ "name": name, "birthdate": birthdate })),
        )
    }

    // ── 以下为 create_account 之后的 OAuth 段（对齐 auth_flow.py 的 9/10 步）──

    /// 普通 JSON POST 头（对齐 Python `_common_headers`）：
    /// 与 [`Self::auth_json_headers`] 的区别是**不带**两个 `x-*` 一次性头。
    ///
    /// `workspace/select` 与 `chatgpt /api/auth/session` 用的就是这套头。
    pub fn common_json_headers(&self, referer: &str) -> Vec<(String, String)> {
        let mut headers = self.base_headers();
        headers.push(("accept".into(), "application/json".into()));
        headers.push(("referer".into(), referer.into()));
        headers
    }

    /// `POST /api/accounts/workspace/select` —— 选 workspace，返回下一跳 `continue_url`。
    ///
    /// 对齐 Python `_workspace_select()`：同源 POST，因此**不带** Origin；
    /// body 只有 `{"workspace_id": ...}`。
    pub fn select_workspace(&self, workspace_id: &str) -> RequestSpec {
        RequestSpec::post_json(
            "auth.workspace_select",
            EP_WORKSPACE_SELECT,
            Some(self.common_json_headers(REFERER_CODEX_CONSENT)),
            Some(json!({ "workspace_id": workspace_id })),
        )
    }

    /// `GET https://chatgpt.com/api/auth/session` —— 拿 `accessToken` / `sessionToken`。
    pub fn chat_session(&self) -> RequestSpec {
        RequestSpec::get("auth.chat_session", EP_CHAT_SESSION)
            .with_headers(self.common_json_headers(CHATGPT_BASE_REFERER))
    }
}

/// 在 `create_account` 之后需要的东西（callback / token / session）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthHandoff {
    /// 归一化后的 `continue_url`（可能已被 workspace/select 替换）。
    pub continue_url: String,
    /// 捕获到的 `https://chatgpt.com/api/auth/callback/openai?code=…`（未被消费）。
    pub callback_url: String,
    /// callback 里的 `code`。
    pub code: String,
    /// OAuth 交换得到的 `access_token`。
    pub access_token: String,
    /// OAuth 交换得到的 `refresh_token`（尽力而为）。
    pub refresh_token: String,
    /// `/api/auth/session` 拿到的 `sessionToken`（cookie 兜底）。
    pub session_token: String,
}

impl OAuthHandoff {
    pub fn has_access_token(&self) -> bool {
        !self.access_token.is_empty()
    }
}

fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─────────────────────────── 响应解析 ───────────────────────────

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Page {
    #[serde(rename = "type", default)]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct AuthorizeContinueResponse {
    #[serde(default)]
    pub page: Option<Page>,
    #[serde(default)]
    pub continue_url: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct CreateAccountResponse {
    #[serde(default)]
    pub continue_url: String,
    #[serde(default)]
    pub page: Option<Page>,
}

fn parse_json_lenient(label: &str, body: &str) -> Result<JsonValue> {
    if body.trim().is_empty() {
        return Ok(JsonValue::Object(Default::default()));
    }
    serde_json::from_str(body).with_context(|| format!("{label} 响应不是合法 JSON: {}", snippet(body)))
}

/// 解析 `authorize/continue` 响应；空响应视为 `{}`（Python 侧同样容错）。
pub fn parse_authorize_continue(body: &str) -> Result<AuthorizeContinueResponse> {
    let value = parse_json_lenient("authorize/continue", body)?;
    serde_json::from_value(value).context("authorize/continue 响应结构不符")
}

/// 解析 `create_account` 响应（关键字段 `continue_url`）。
pub fn parse_create_account(body: &str) -> Result<CreateAccountResponse> {
    let value = parse_json_lenient("create_account", body)?;
    serde_json::from_value(value).context("create_account 响应结构不符")
}

/// 服务端错误体（`{"error":{"message":...,"code":...}}` 或 `{"detail":...}`）。
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ApiErrorBody {
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub error: Option<ApiErrorDetail>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ApiErrorDetail {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub code: String,
}

/// 把非 2xx 响应转成一句人话（日志/报错用）。
pub fn describe_api_error(status: u16, body: &str) -> String {
    match serde_json::from_str::<ApiErrorBody>(body) {
        Ok(parsed) => {
            let detail = parsed.error.as_ref().map(|e| {
                if e.code.is_empty() {
                    e.message.clone()
                } else {
                    format!("{} (code={})", e.message, e.code)
                }
            });
            let text = detail
                .filter(|s| !s.trim().is_empty())
                .or_else(|| Some(parsed.detail).filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| snippet(body));
            format!("HTTP {status}: {text}")
        }
        Err(_) => format!("HTTP {status}: {}", snippet(body)),
    }
}

fn snippet(body: &str) -> String {
    let head: String = body.chars().take(200).collect();
    if body.chars().count() > 200 {
        format!("{head}…")
    } else {
        head
    }
}

// ─────────────────────────── 落地 URL 分类 ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Signup,
    Login,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landing {
    /// 新账号（走注册链）。
    New,
    /// 已有账号（走 OTP 登录）。
    Existing,
    /// 判不出（调用方应回退到 authorize/continue 探测）。
    Unknown,
}

/// 把 authorize 落地 URL 映射成 new/existing/unknown，对齐 Python `_classify_authorize_landing`。
///
/// `/email-verification` 在注册链里含义是"新账号"，在登录链里是"已有账号"，所以必须按 intent 分流。
pub fn classify_landing(landing_url: &str, intent: Intent) -> Landing {
    let url = landing_url.trim().to_ascii_lowercase();
    if url.is_empty() {
        return Landing::Unknown;
    }
    if url.contains("/create-account") || url.contains("/about-you") {
        return Landing::New;
    }
    if url.contains("/log-in") {
        return Landing::Existing;
    }
    if url.contains("/email-verification") {
        return match intent {
            Intent::Signup => Landing::New,
            Intent::Login => Landing::Existing,
        };
    }
    Landing::Unknown
}

// ─────────────────── authorize URL：获取 / 兜底补参 / 解析 ───────────────────

/// 从 `GET /api/auth/csrf` 的响应里取 `csrfToken`（对齐 Python `get_csrf_token`）。
pub fn parse_csrf_token(body: &str) -> Result<String> {
    let value = parse_json_lenient("chatgpt csrf", body)?;
    let token = value
        .get("csrfToken")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("csrfToken 缺失（响应={}）", snippet(body));
    }
    Ok(token)
}

/// 从 `POST /api/auth/signin/openai` 的响应里取 `url`（就是 authorize URL）。
pub fn parse_signin_url(body: &str) -> Result<String> {
    let value = parse_json_lenient("chatgpt signin", body)?;
    let url = value
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if url.is_empty() {
        bail!("signin 响应缺少 authorize url（响应={}）", snippet(body));
    }
    Ok(url)
}

/// 补齐 authorize URL 上会漂的上下文参数（对齐 Python `_ensure_authorize_context`）。
///
/// **只补缺失的键**，已存在的原样保留（服务端给什么就用什么）。缺 `login_hint`
/// 的话 authorize 那一跳送不到邮箱，后面必然 409 invalid_state。
pub fn ensure_authorize_context(
    authorize_url: &str,
    email: &str,
    device_id: &str,
    auth_session_logging_id: &str,
) -> String {
    let url = authorize_url.trim();
    if url.is_empty() || !url.to_ascii_lowercase().contains("auth.openai.com") {
        return url.to_string();
    }
    let (base, query) = match url.split_once('?') {
        Some((base, rest)) => (base, rest),
        None => (url, ""),
    };
    let existing_keys: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            pair.split_once('=')
                .map(|(key, _)| key)
                .unwrap_or(pair)
                .to_string()
        })
        .map(|key| url_decode(&key).to_ascii_lowercase())
        .collect();

    let mut required: Vec<(&str, &str)> = vec![
        ("ext-oai-did", device_id),
        ("auth_session_logging_id", auth_session_logging_id),
        ("screen_hint", "login_or_signup"),
        ("ccaps", CC_CAPS),
        ("auth_return_target_category", AUTH_RETURN_TARGET_CATEGORY),
    ];
    if !email.trim().is_empty() {
        required.push(("login_hint", email.trim()));
    }

    let mut out = query.to_string();
    for (key, value) in required {
        if value.trim().is_empty() {
            continue;
        }
        if existing_keys.iter().any(|existing| existing == key) {
            continue;
        }
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&urlencode(key));
        out.push('=');
        out.push_str(&urlencode(value));
    }
    if out.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{out}")
    }
}

/// 从 authorize 落地的 HTML 里兜底抽 `oai-did`（cookie 缺失时用）。
pub fn device_id_from_html(html: &str) -> Option<String> {
    let anchor = html.find("oai-did")?;
    let tail = html[anchor..].as_bytes();
    for window in tail.windows(36) {
        let is_uuid = window.iter().enumerate().all(|(index, byte)| {
            if index == 8 || index == 13 || index == 18 || index == 23 {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
        if is_uuid {
            if let Ok(found) = std::str::from_utf8(window) {
                return Some(found.to_string());
            }
        }
    }
    None
}

// ─────────────────────────── 随机身份 ───────────────────────────

const PASSWORD_LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const PASSWORD_UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const PASSWORD_DIGIT: &[u8] = b"23456789";
const PASSWORD_SYMBOL: &[u8] = b"!@#$%^&*-_=+?";

/// 生成注册密码：保证四类字符各至少一个（对齐 Python `_random_password`）。
pub fn random_password(len: usize) -> String {
    let len = len.max(8);
    let mut rng = rand::thread_rng();
    let mut chars: Vec<u8> = vec![
        PASSWORD_LOWER[rng.gen_range(0..PASSWORD_LOWER.len())],
        PASSWORD_UPPER[rng.gen_range(0..PASSWORD_UPPER.len())],
        PASSWORD_DIGIT[rng.gen_range(0..PASSWORD_DIGIT.len())],
        PASSWORD_SYMBOL[rng.gen_range(0..PASSWORD_SYMBOL.len())],
    ];
    let all: Vec<u8> = PASSWORD_LOWER
        .iter()
        .chain(PASSWORD_UPPER)
        .chain(PASSWORD_DIGIT)
        .chain(PASSWORD_SYMBOL)
        .copied()
        .collect();
    while chars.len() < len {
        chars.push(all[rng.gen_range(0..all.len())]);
    }
    // 打乱，避免固定前四类顺序
    for i in (1..chars.len()).rev() {
        let j = rng.gen_range(0..=i);
        chars.swap(i, j);
    }
    String::from_utf8(chars).unwrap_or_default()
}

const FIRST_NAMES: &[&str] = &[
    "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas",
    "Charles", "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica",
    "Sarah", "Karen",
];

const LAST_NAMES: &[&str] = &[
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez",
    "Martinez", "Wilson", "Anderson", "Taylor", "Thomas",
];

/// 随机英文姓名（对齐 Python 的 `_FIRST`/`_LAST` 列表）。
pub fn random_name() -> String {
    let mut rng = rand::thread_rng();
    let first = FIRST_NAMES[rng.gen_range(0..FIRST_NAMES.len())];
    let last = LAST_NAMES[rng.gen_range(0..LAST_NAMES.len())];
    format!("{first} {last}")
}

/// 随机生日 `YYYY-MM-DD`，年份 1985..=2000（对齐 Python）。
pub fn random_birthdate() -> String {
    let mut rng = rand::thread_rng();
    let year: u32 = rng.gen_range(1985..=2000);
    let month: u32 = rng.gen_range(1..=12);
    let day: u32 = rng.gen_range(1..=28);
    format!("{year:04}-{month:02}-{day:02}")
}

/// 超时值对外暴露（编排层/CLI 展示用）。
pub const REQUEST_TIMEOUT_SECS: u64 = DEFAULT_TIMEOUT_SECS;

// ─────────────────── create_account 之后：workspace → callback → token ───────────────────

/// 一次 OAuth 授权码交换的参数（对齐 Python `oauth_token_exchange()` 的 `base_form`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthParams {
    pub client_id: String,
    pub redirect_uri: String,
    /// PKCE `code_verifier`（尽力模式，可能没有）。
    pub code_verifier: Option<String>,
    /// 少数服务端要求的 `audience`。
    pub audience: Option<String>,
    /// 少数服务端要求的 `scope`。
    pub scope: Option<String>,
}

impl Default for OAuthParams {
    fn default() -> Self {
        Self {
            client_id: DEFAULT_OAUTH_CLIENT_ID.to_string(),
            redirect_uri: DEFAULT_REDIRECT_URI.to_string(),
            code_verifier: None,
            audience: None,
            scope: None,
        }
    }
}

impl OAuthParams {
    pub fn with_verifier(mut self, verifier: impl Into<String>) -> Self {
        let verifier = verifier.into();
        self.code_verifier = if verifier.is_empty() {
            None
        } else {
            Some(verifier)
        };
        self
    }

    /// 表单字段（顺序对齐 Python：`grant_type, client_id, code, redirect_uri`，
    /// 之后按需追加 `code_verifier` / `audience` / `scope`）。
    pub fn form_pairs(&self, code: &str) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            ("grant_type", "authorization_code".to_string()),
            ("client_id", self.client_id.clone()),
            ("code", code.to_string()),
            ("redirect_uri", self.redirect_uri.clone()),
        ];
        if let Some(verifier) = &self.code_verifier {
            pairs.push(("code_verifier", verifier.clone()));
        }
        if let Some(audience) = &self.audience {
            pairs.push(("audience", audience.clone()));
        }
        if let Some(scope) = &self.scope {
            pairs.push(("scope", scope.clone()));
        }
        pairs
    }

    /// `urlencode(form)` 的正文。
    pub fn form_body(&self, code: &str) -> String {
        self.form_pairs(code)
            .iter()
            .map(|(key, value)| format!("{}={}", urlencode(key), urlencode(value)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// `oauth/token` 的请求头（对齐 Python `oauth_token_exchange()` 里的 `headers`）。
pub fn token_exchange_headers() -> Vec<(String, String)> {
    vec![
        (
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ),
        ("accept".into(), "application/json".into()),
        ("origin".into(), AUTH_BASE.into()),
        ("referer".into(), REFERER_CODEX_CONSENT.into()),
        ("sec-fetch-dest".into(), "empty".into()),
        ("sec-fetch-mode".into(), "cors".into()),
        ("sec-fetch-site".into(), "same-origin".into()),
    ]
}

/// `POST /oauth/token` —— 用 callback 里的 `code` 换 `access_token` / `id_token` / `refresh_token`。
pub fn exchange_code_for_token(code: &str, params: &OAuthParams) -> RequestSpec {
    RequestSpec::post_form(
        "auth.oauth_token",
        EP_OAUTH_TOKEN,
        Some(token_exchange_headers()),
        params.form_body(code),
    )
}

/// `oauth/token` 的响应。
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct TokenExchangeResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// 解析 `oauth/token` 响应；非 2xx 或缺 `access_token` 都算失败。
pub fn parse_token_exchange(status: u16, body: &str) -> Result<TokenExchangeResponse> {
    if !(200..300).contains(&status) {
        bail!("OAuth token 交换失败: {}", describe_api_error(status, body));
    }
    let parsed: TokenExchangeResponse = serde_json::from_str(body)
        .with_context(|| format!("oauth/token 响应结构不符: {}", snippet(body)))?;
    if parsed.access_token.is_empty() {
        bail!("oauth/token 响应缺少 access_token: {}", snippet(body));
    }
    Ok(parsed)
}

/// `POST /api/accounts/workspace/select` 的响应。
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSelectResponse {
    #[serde(default)]
    pub continue_url: String,
}

/// 解析 `workspace/select` 响应（关键字段 `continue_url`）。
pub fn parse_workspace_select(status: u16, body: &str) -> Result<WorkspaceSelectResponse> {
    if !(200..300).contains(&status) {
        bail!("workspace/select 失败: {}", describe_api_error(status, body));
    }
    let value = parse_json_lenient("workspace/select", body)?;
    serde_json::from_value(value).context("workspace/select 响应结构不符")
}

/// `GET https://chatgpt.com/api/auth/session` 的响应（只关心两个 token）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatSession {
    pub access_token: String,
    pub session_token: String,
}

/// 解析 chatgpt 会话响应（camelCase 与 snake_case 都认）。
pub fn parse_chat_session(body: &str) -> Result<ChatSession> {
    let value = parse_json_lenient("chatgpt session", body)?;
    let pick = |camel: &str, snake: &str| {
        value
            .get(camel)
            .or_else(|| value.get(snake))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    Ok(ChatSession {
        access_token: pick("accessToken", "access_token"),
        session_token: pick("sessionToken", "session_token"),
    })
}

/// 相对 URL → 绝对 URL（对齐 Python `urljoin` 的常见形态）。
pub fn absolute_url(url: &str, base: &str) -> String {
    let url = url.trim();
    if url.is_empty() {
        return String::new();
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    if let Some(rest) = url.strip_prefix("//") {
        return format!("https://{rest}");
    }
    let origin = base.split("://").nth(1).unwrap_or(base);
    let origin = origin.split('/').next().unwrap_or(origin);
    let host = if origin.is_empty() {
        "auth.openai.com"
    } else {
        origin
    };
    if url.starts_with('/') {
        format!("https://{host}{url}")
    } else {
        format!("https://{host}/{url}")
    }
}

/// 是否 workspace 页面（Python `"/workspace" in out`）。
pub fn is_workspace_page(url: &str) -> bool {
    url.to_ascii_lowercase().contains("/workspace")
}

/// 是否 NextAuth callback。
pub fn is_callback_url(url: &str) -> bool {
    url.contains(CALLBACK_PATH)
}

/// 取 URL query 里第一个命中的键（对齐 Python `_extract_query_first`）。
pub fn query_first(url: &str, keys: &[&str]) -> String {
    let query = match url.split_once('?') {
        Some((_, rest)) => rest.split('#').next().unwrap_or(""),
        None => return String::new(),
    };
    let pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter_map(|item| item.split_once('='))
        .collect();
    for key in keys {
        if let Some((_, value)) = pairs.iter().find(|(k, _)| k == key) {
            let decoded = url_decode(value);
            if !decoded.is_empty() {
                return decoded;
            }
        }
    }
    String::new()
}

/// callback URL 里的授权码。
pub fn callback_code(url: &str) -> Option<String> {
    let code = query_first(url, &["code"]);
    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

/// workspace 页面 URL 里的 workspace id（`workspace_id` 优先，其次 `id`）。
pub fn workspace_id_from_url(url: &str) -> Option<String> {
    let id = query_first(url, &["workspace_id", "id"]);
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// 从 Cookie 头字符串里取某个 cookie 的值（名字大小写不敏感）。
pub fn cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    cookie_header.split(';').find_map(|item| {
        let (key, value) = item.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case(name) {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        } else {
            None
        }
    })
}

/// 从 `oai-client-auth-session` cookie 里解出 workspace id。
///
/// 兼容 Python `_extract_workspace_id()`：取前两段 base64url(JSON)，
/// 先看 `workspace_id`，再看 `workspaces[0].id`。
pub fn workspace_id_from_auth_session(value: &str) -> Option<String> {
    for segment in value.split('.').take(2) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Ok(raw) = base64url_decode(segment) else {
            continue;
        };
        let Ok(decoded) = serde_json::from_slice::<JsonValue>(&raw) else {
            continue;
        };
        if !decoded.is_object() {
            continue;
        }
        if let Some(id) = decoded
            .get("workspace_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(id.to_string());
        }
        if let Some(items) = decoded.get("workspaces").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(id) = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

/// 从 Cookie 头里直接抽 workspace id（`oai-client-auth-session`）。
pub fn workspace_id_from_cookie_header(cookie_header: &str) -> Option<String> {
    cookie_value(cookie_header, "oai-client-auth-session")
        .and_then(|value| workspace_id_from_auth_session(&value))
}

/// 从 workspace 页 HTML 里兜底抽 workspace id（无 regex 依赖）。
pub fn workspace_id_from_html(html: &str) -> Option<String> {
    let text = html.replace("\\\"", "\"");
    for key in ["\"workspace_id\"", "\"workspaceId\"", "\"workspace_id\":"] {
        let search = key.trim_end_matches(':');
        if let Some(found) = quoted_value_after(&text, search) {
            if looks_like_workspace_id(&found) {
                return Some(found);
            }
        }
    }
    // 兜底：`"workspaces": [{ "id": "<uuid>" }]`（react-router 流式载荷里的
    // 变体是 `"id","<uuid>"`，两种都认）。
    if let Some(anchor) = text.find("\"workspaces\"") {
        let end = (anchor + 1600).min(text.len());
        let window = &text[anchor..end];
        for marker in ["\"id\":", "\"id\","] {
            if let Some((_, rest)) = window.split_once(marker) {
                if let Some(found) = quoted_value_after(rest, "") {
                    if looks_like_workspace_id(&found) {
                        return Some(found);
                    }
                }
            }
        }
    }
    None
}

/// 在 `haystack` 里 `key` 之后找下一个引号字符串。
fn quoted_value_after(haystack: &str, key: &str) -> Option<String> {
    let start = if key.is_empty() {
        0
    } else {
        haystack.find(key)? + key.len()
    };
    let rest = &haystack[start..];
    let open = rest.find('"')?;
    let after = &rest[open + 1..];
    let close = after.find('"')?;
    let value = after[..close].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn looks_like_workspace_id(value: &str) -> bool {
    value.len() == 36
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
        && value.chars().filter(|c| *c == '-').count() == 4
}

fn base64url_decode(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let normalized: String = text
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let padded = format!(
        "{}{}",
        normalized,
        "=".repeat((4 - normalized.len() % 4) % 4)
    );
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|err| err.to_string())
}

/// 从 OAuth 授权的白名单字符集出发的百分号编码（Python `quote_plus`）。
pub fn urlencode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 百分号解码（Python `parse_qsl` 的反向；`+` 视作空格）。
pub fn url_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push((high * 16 + low) as u8);
                        index += 3;
                    }
                    _ => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
