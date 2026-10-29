//! 传输层：注册链用的 HTTP Client 包装（**wreq / BoringSSL**）。
//!
//! 上游 Python 侧走 `http_client_wreq.py`（wreq = TLS / HTTP2 指纹伪装）。本 crate
//! 现在同样走 **wreq**：TLS 用 BoringSSL（btls），默认套 Chrome 的 JA3 / JA4 /
//! HTTP/2 SETTINGS + 窗口 + 伪头顺序，不再是 reqwest 的 OpenSSL/rustls 指纹。
//!
//! 所有指纹差异都收敛在本文件里：换 emulation / 换传输库只需替换 [`Client`] 的
//! 内部实现，[`RequestSpec`] 与上层流程（`auth` / `authorize` / `mod`）不变。
//!
//! ## 构建要求
//!
//! BoringSSL 要本地编译：MSVC + nasm + Strawberry Perl + LLVM(libclang)。
//! 必须用仓库根的 `build.ps1`（自动 call `vcvars64.bat` 并设 `LIBCLANG_PATH`）。
//!
//! ## emulation
//!
//! 默认 `wreq_util::Emulation::Chrome149`（wreq-util 0.2.0 里的最高档 Chrome），
//! 可用环境变量 `TURB_WREQ_EMULATION` 覆盖（值形如 `Chrome149` / `Chrome146`，
//! 大小写 / `_` / `-` 不敏感）。
//!
//! ## 离线可测的部分（不碰网络）
//!
//!   * [`RetryPolicy`] 的 `should_retry` / `delay_ms`
//!   * [`RequestSpec`] 的构造、header 查找、日志脱敏
//!   * [`normalize_proxy_url`]、[`parse_emulation`] 与 [`Client::build`]（只构造，不发请求）

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
use wreq::cookie::{CookieStore, Cookies, Jar};
use wreq::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, USER_AGENT};
use wreq_util::{Emulation, Profile};

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// 默认 emulation（wreq-util 0.2.0 提供的最高 Chrome 档）。
///
/// 注意类型是 [`Profile`]：`wreq_util::Emulation::Chrome149` 是挂在 wreq-util
/// 的 `Emulation` 配置结构体上的关联常量，值的类型是 `Profile`。
pub const DEFAULT_EMULATION: Profile = Emulation::Chrome149;

/// 覆盖 emulation 的环境变量名。
pub const EMULATION_ENV: &str = "TURB_WREQ_EMULATION";

/// HTTP 方法（只用到 GET/POST，够注册链用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Get => f.write_str("GET"),
            Method::Post => f.write_str("POST"),
        }
    }
}

impl Method {
    fn to_wreq(self) -> wreq::Method {
        match self {
            Method::Get => wreq::Method::GET,
            Method::Post => wreq::Method::POST,
        }
    }
}

/// 非 JSON 的请求正文（`oauth/token` 的 form、`sentinel/req` 的 text/plain）。
///
/// 之所以不复用 [`RequestSpec::body`]：`serde_json::Value` 的键序是字典序，
/// 而这些请求在 Python 侧用的是 `urlencode()` / `json.dumps(separators=(",",":"))`
/// 的**固定字段顺序**，必须原样发出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBody {
    pub content_type: &'static str,
    pub text: String,
}

/// 一个待发送的请求：纯数据，先构造、后发送，方便离线断言。
#[derive(Debug, Clone)]
pub struct RequestSpec {
    /// 日志/计划里用的短标签，例如 `auth.user_register`。
    pub label: &'static str,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<JsonValue>,
    /// 原始正文（与 `body` 互斥）。表单 / `text/plain` 请求走这里。
    pub raw_body: Option<RawBody>,
}

impl RequestSpec {
    pub fn get(label: &'static str, url: impl Into<String>) -> Self {
        Self {
            label,
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            raw_body: None,
        }
    }

    pub fn post_json(
        label: &'static str,
        url: impl Into<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<JsonValue>,
    ) -> Self {
        Self {
            label,
            method: Method::Post,
            url: url.into(),
            headers: headers.unwrap_or_default(),
            body,
            raw_body: None,
        }
    }

    /// POST 原始正文（自带 content-type）。用于 form 与 `text/plain` 请求。
    pub fn post_raw(
        label: &'static str,
        url: impl Into<String>,
        headers: Option<Vec<(String, String)>>,
        content_type: &'static str,
        text: impl Into<String>,
    ) -> Self {
        Self {
            label,
            method: Method::Post,
            url: url.into(),
            headers: headers.unwrap_or_default(),
            body: None,
            raw_body: Some(RawBody {
                content_type,
                text: text.into(),
            }),
        }
    }

    /// POST `x-www-form-urlencoded`（对齐 Python `urlencode()` + `data=`）。
    pub fn post_form(
        label: &'static str,
        url: impl Into<String>,
        headers: Option<Vec<(String, String)>>,
        form: impl Into<String>,
    ) -> Self {
        Self::post_raw(
            label,
            url,
            headers,
            "application/x-www-form-urlencoded",
            form,
        )
    }

    /// 原始正文（若有）。
    pub fn raw(&self) -> Option<&str> {
        self.raw_body.as_ref().map(|r| r.text.as_str())
    }

    /// 待发送字节（JSON 正文 / 原始正文 / 无）。
    pub fn payload(&self) -> Option<String> {
        match (&self.raw_body, &self.body) {
            (Some(raw), _) => Some(raw.text.clone()),
            (None, Some(body)) => Some(body.to_string()),
            (None, None) => None,
        }
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        for (name, value) in headers {
            self.set_header(&name, &value);
        }
        self
    }

    /// 同名 header 覆盖写（对齐浏览器行为，避免出现两份相同头）。
    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some(slot) = self
            .headers
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            slot.1 = value.to_string();
        } else {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `METHOD url (label)`，dry-run 打印用。
    pub fn describe(&self) -> String {
        format!("{} {} ({})", self.method, self.url, self.label)
    }

    /// 打印用：敏感头只留前缀。
    pub fn describe_with_headers(&self) -> String {
        let mut out = self.describe();
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            let shown = if lower.contains("token")
                || lower.contains("authorization")
                || lower.contains("cookie")
            {
                let head: String = value.chars().take(12).collect();
                format!("{head}…<redacted>")
            } else {
                value.clone()
            };
            out.push_str(&format!("\n    {name}: {shown}"));
        }
        if let Some(body) = &self.body {
            out.push_str(&format!("\n    body: {body}"));
        }
        if let Some(raw) = &self.raw_body {
            out.push_str(&format!(
                "\n    body[{}]: {}",
                raw.content_type, raw.text
            ));
        }
        out
    }
}

/// 重试策略（纯逻辑，可单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// 总尝试次数（含首次）。
    pub max_attempts: u32,
    /// 退避基数：第 n 次重试等 base * 2^(n-1)。
    pub base_delay_ms: u64,
    /// 429 是否重试。
    pub retry_on_429: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 400,
            retry_on_429: true,
        }
    }
}

impl RetryPolicy {
    /// `attempt` 是已经发生的第几次尝试（1-based）；`status` 是本次结果（None = 传输层错误）。
    pub fn should_retry(&self, attempt: u32, status: Option<u16>) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }
        match status {
            None => true,
            Some(429) => self.retry_on_429,
            Some(code) => (500..600).contains(&code),
        }
    }

    /// 第 `attempt` 次尝试失败后该等多久（指数退避）。
    pub fn delay_ms(&self, attempt: u32) -> u64 {
        let exp = attempt.saturating_sub(1).min(6);
        self.base_delay_ms.saturating_mul(1u64 << exp)
    }
}

/// 响应：与传输库解耦，方便上层/测试断言。
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.body)
            .with_context(|| format!("响应 JSON 解析失败（status={}）: {}", self.status, truncate(&self.body, 300)))
    }
}

/// 便捷：拿响应正文。
pub fn body_string(resp: &HttpResponse) -> &str {
    &resp.body
}

fn truncate(text: &str, limit: usize) -> String {
    let head: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        format!("{head}…")
    } else {
        head
    }
}

/// 把 `host:port` 补成 `http://host:port`；非法输入报错。
///
/// 用 `wreq::Uri`（http crate 的 Uri）做校验：它认任意 scheme
/// （`http` / `https` / `socks5` / `socks5h` …）和 `user:pass@` 形式的 userinfo。
pub fn normalize_proxy_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("代理地址为空");
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let uri: wreq::Uri = with_scheme
        .parse()
        .with_context(|| format!("代理地址不是合法 URL: {with_scheme}"))?;
    let host = uri.host().unwrap_or_default();
    if host.is_empty() {
        bail!("代理地址缺少 host/port: {with_scheme}");
    }
    Ok(with_scheme)
}

/// 把 `TURB_WREQ_EMULATION` 的字符串映射成 [`Profile`]。
///
/// 接受 `Chrome149` / `chrome_149` / `chrome-149` 这类写法（大小写与分隔符不敏感），
/// 也接受其它 profile（`Firefox148`、`Edge148`、`Safari26`… 取决于 wreq-util 版本）。
/// 未知名字返回 `None`，由调用方决定回退。
pub fn parse_emulation(raw: &str) -> Option<Profile> {
    let want = normalize_emulation_key(raw);
    if want.is_empty() {
        return None;
    }
    Profile::VARIANTS
        .iter()
        .copied()
        .find(|candidate| normalize_emulation_key(&format!("{candidate:?}")) == want)
}

fn normalize_emulation_key(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// 解析 emulation：环境变量优先，缺省 [`DEFAULT_EMULATION`]。
pub fn emulation_from_env() -> Profile {
    let raw = std::env::var(EMULATION_ENV).unwrap_or_default();
    if raw.trim().is_empty() {
        return DEFAULT_EMULATION;
    }
    match parse_emulation(&raw) {
        Some(emulation) => emulation,
        None => {
            warn!(
                "[http] {EMULATION_ENV}={raw:?} 不认识，回退 {:?}",
                DEFAULT_EMULATION
            );
            DEFAULT_EMULATION
        }
    }
}

/// wreq 包装：Chrome emulation（TLS/HTTP2 指纹）+ cookie jar + 代理 + 重试。
pub struct Client {
    inner: wreq::Client,
    jar: Arc<Jar>,
    pub policy: RetryPolicy,
    pub proxy: Option<String>,
    pub user_agent: String,
    /// 实际生效的 TLS/HTTP2 emulation（`TURB_WREQ_EMULATION` 可覆盖）。
    pub emulation: Profile,
}

impl Client {
    /// 只构造，不发请求 —— 可以在离线环境调用。
    ///
    /// emulation 取 `TURB_WREQ_EMULATION` 或默认 [`DEFAULT_EMULATION`]；要按设备指纹
    /// 切档位用 [`Client::build_with_emulation`]。
    pub fn build(user_agent: &str, proxy: Option<&str>, policy: RetryPolicy) -> Result<Self> {
        Self::build_with_emulation(user_agent, proxy, policy, None)
    }

    /// 指定 emulation 的构造入口（`None` = 走环境变量 / 默认档）。
    ///
    /// 设备指纹路径用这个把 TLS/HTTP2 档位和 UA 的 Chrome 版本对齐
    /// （UA 说 145、握手按 149 就是一眼假的组合）。
    pub fn build_with_emulation(
        user_agent: &str,
        proxy: Option<&str>,
        policy: RetryPolicy,
        emulation: Option<Profile>,
    ) -> Result<Self> {
        let jar = Arc::new(Jar::default());
        let emulation = emulation.unwrap_or_else(emulation_from_env);

        let mut builder = wreq::Client::builder()
            // Chrome TLS(JA3/JA4) + HTTP/2 (SETTINGS/窗口/伪头顺序) + 默认头。
            // 注意：emulation 必须在 http1/http2/tls 细调之前设置（会覆盖）。
            .emulation(emulation)
            .cookie_provider(jar.clone())
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            // 手动跟随重定向，注册链需要看 302 的 Location。
            .redirect(wreq::redirect::Policy::none());

        // 上层显式给的 UA 覆盖 profile 自带的那条（`SENTINEL_USER_AGENT` 仍然生效），
        // 其余 profile 头（sec-ch-ua / accept / accept-language …）保持不变。
        if !user_agent.trim().is_empty() {
            builder = builder.user_agent(user_agent);
        }

        if let Some(raw) = proxy {
            if !raw.trim().is_empty() {
                let url = normalize_proxy_url(raw)?;
                let proxy = wreq::Proxy::all(url.as_str())
                    .with_context(|| format!("代理初始化失败: {url}"))?;
                builder = builder.proxy(proxy);
            }
        }

        let inner = builder.build().context("构建 wreq HTTP client 失败")?;
        debug!(
            "[http] client 就绪：emulation={emulation:?} proxy={} timeout={DEFAULT_TIMEOUT_SECS}s",
            proxy.map(str::trim).filter(|p| !p.is_empty()).unwrap_or("<直连>")
        );
        Ok(Self {
            inner,
            jar,
            policy,
            proxy: proxy.map(str::to_string),
            user_agent: user_agent.to_string(),
            emulation,
        })
    }

    /// 当前 jar 里对 `url` 的 Cookie 头（落库/调试用）。
    ///
    /// wreq 的 [`Jar`] 不再提供 `cookies(&url)`，改走 [`CookieStore::cookies`]：
    /// 按 HTTP/1.1 规则序列化成单条 `Cookie` 头（`a=1; b=2`），与 reqwest 时代一致。
    pub fn cookie_header_for(&self, url: &str) -> String {
        let Ok(uri) = url.parse::<wreq::Uri>() else {
            return String::new();
        };
        match self.jar.cookies(&uri, wreq::Version::HTTP_11) {
            Cookies::Compressed(value) => value.to_str().unwrap_or_default().to_string(),
            Cookies::Uncompressed(values) => values
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join("; "),
            _ => String::new(),
        }
    }

    /// 发送请求（带重试）。5xx / 429 / 传输错误按 [`RetryPolicy`] 重试。
    pub async fn execute(&self, spec: &RequestSpec) -> Result<HttpResponse> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let result = self.send_once(spec).await;

            let (retryable, status) = match &result {
                Ok(resp) => (
                    !resp.is_success() && self.policy.should_retry(attempt, Some(resp.status)),
                    Some(resp.status),
                ),
                Err(_) => (self.policy.should_retry(attempt, None), None),
            };

            if !retryable {
                return result;
            }

            let delay = self.policy.delay_ms(attempt);
            match status {
                Some(code) => warn!(
                    "[http] {} 返回 {}（第 {}/{} 次），{}ms 后重试",
                    spec.label, code, attempt, self.policy.max_attempts, delay
                ),
                None => warn!(
                    "[http] {} 传输失败（第 {}/{} 次），{}ms 后重试",
                    spec.label, attempt, self.policy.max_attempts, delay
                ),
            }
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    async fn send_once(&self, spec: &RequestSpec) -> Result<HttpResponse> {
        let mut headers = HeaderMap::new();
        for (name, value) in &spec.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("非法 header 名: {name}"))?;
            let value =
                HeaderValue::from_str(value).with_context(|| format!("非法 header 值: {value}"))?;
            headers.insert(name, value);
        }
        if spec
            .headers
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("user-agent"))
        {
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&self.user_agent).context("UA 非法")?,
            );
        }
        if spec.body.is_some()
            && spec
                .headers
                .iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case("content-type"))
        {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        if let Some(raw) = &spec.raw_body {
            if spec
                .headers
                .iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case("content-type"))
            {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str(raw.content_type).context("raw body content-type 非法")?,
                );
            }
        }

        debug!("[http] {} {}", spec.method, spec.url);
        let mut request = self
            .inner
            .request(spec.method.to_wreq(), spec.url.as_str())
            .headers(headers);
        if let Some(raw) = &spec.raw_body {
            request = request.body(raw.text.clone());
        } else if let Some(body) = &spec.body {
            request = request.body(body.to_string());
        }

        let resp = request.send().await.with_context(|| {
            format!("请求失败: {} {} ({})", spec.method, spec.url, spec.label)
        })?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        let body = resp.text().await.context("读取响应正文失败")?;
        if matches!(
            std::env::var("SENTINEL_LOG").unwrap_or_default().as_str(),
            "debug" | "trace"
        ) {
            let preview: String = body.chars().take(200).collect();
            eprintln!("[http] <- {} {} ({}) {}", status, spec.method, spec.label, preview);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
