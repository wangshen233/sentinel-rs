//! sentinel token 源：`requirements → /sentinel/req → turnstile t → (可选) SO`。
//!
//! 这是 Python `sentinel_py.get_sentinel_token_py()` 的 Rust 版，链路逐段对齐
//! （字段名、请求头、JSON 键序都一样）：
//!
//! | 步骤 | Python | 本模块 |
//! |---|---|---|
//! | 1. requirements token | `requirements_token(profile, sid)` | [`crate::token::requirements_token`] |
//! | 2. 换 challenge | `_fetch_challenge()` → `POST /backend-api/sentinel/req` | [`ChallengeTransport`] |
//! | 3. `p`（enforcement） | `enforcement_token(challenge, profile, sid)`，失败回退 requirements | [`crate::token::enforcement_token`] |
//! | 4. `t`（turnstile） | `_run_program(turnstile.dx, request_p)` | [`MintEngine::mint_t`] → `mint::mint_t` |
//! | 5. `so`（可选） | `collector_dx` + `snapshot_dx` | [`MintEngine::mint_so`]（**TODO：桩**） |
//! | 6. 组装 | `json.dumps({"p","t","c","id","flow"}, separators=(",",":"))` | [`token_payload_json`] / [`so_payload_json`] |
//!
//! ### 为什么同步 trait 里还能发 HTTP
//! [`SentinelTokenSource::token`] 是同步的（编排层与单测都按同步用），但 `http::Client`
//! 是 async 的。所以 [`HttpTransport`] 起一个短命线程 + 它自己的 current-thread
//! runtime 去 `block_on`，结果经 channel 回传 —— 这样既不会在调用方的 tokio runtime
//! 里嵌套 `block_on`（那会 panic），也不要求调用方是 multi-thread runtime。
//! 测试则完全绕开 HTTP：注入 [`ChallengeTransport`] / [`MintEngine`] 的闭包实现即可。
//!
//! ### 与 Python 的已知差异
//! * Python 的 `p` 用 `request_p`（requirements token）当 dx 程序的 XOR key，本模块一致。
//! * `sid` / PoW seed 每次都新铸（Python 每次调用 `uuid.uuid4()`），因此同一
//!   `flow` 连两次的 token 一定不同 —— 与线上 sdk.js 行为一致。
//! * SO token 走 [`crate::so::mint_so_with_rng`]（真随机的事件序列）；拿不到 so blob
//!   时降级为"不带 `openai-sentinel-so-token` 头"，与 Python 同路径行为一致。

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value as JsonValue;
use tracing::{debug, info, warn};

use super::http;
use super::{SentinelToken, SentinelTokenSource};
use crate::fingerprint::DeviceFingerprint;
use crate::mint;
use crate::token::{
    enforcement_token, json_string, requirements_token, Profile, ProfileOptions, Rng, TokenCtx,
};

// ─────────────────────────── 常量 ───────────────────────────

/// `/sentinel/req` 端点（与 Python `SENTINEL_REQ_URL` 一致）。
pub const SENTINEL_REQ_URL: &str = "https://sentinel.openai.com/backend-api/sentinel/req";
/// sentinel frame 页面（Referer 用）。
pub const SENTINEL_FRAME_URL: &str = "https://sentinel.openai.com/backend-api/sentinel/frame.html";
/// sentinel 站点 Origin。
pub const SENTINEL_ORIGIN: &str = "https://sentinel.openai.com";
/// sdk.js 版本号（与 [`crate::token::SENTINEL_VERSION`] 同一个值）。
pub const SENTINEL_VERSION: &str = crate::token::SENTINEL_VERSION;

/// `/sentinel/req` 的 content-type（Python `REQ_HEADERS["content-type"]`）。
pub const REQ_CONTENT_TYPE: &str = "text/plain;charset=UTF-8";

/// 注册链用到的 flow 名（对齐 `auth_flow.py` 里的字面量）。
pub const FLOW_AUTHORIZE_CONTINUE: &str = "authorize_continue";
pub const FLOW_USERNAME_PASSWORD_CREATE: &str = "username_password_create";
pub const FLOW_EMAIL_OTP: &str = "email_otp";
pub const FLOW_EMAIL_OTP_VALIDATE: &str = "email_otp_validate";
pub const FLOW_CREATE_ACCOUNT: &str = "oauth_create_account";

/// Referer：`frame.html?sv=<sdk 版本>`。
pub fn frame_referer() -> String {
    format!("{SENTINEL_FRAME_URL}?sv={SENTINEL_VERSION}")
}

/// `/sentinel/req` 的请求头（对齐 Python `REQ_HEADERS`）。
///
/// 注意：这里**不**带 `user-agent`，由 [`super::http::Client`] 统一补上（保持
/// 指纹只在一处配置）。
pub fn request_headers(accept_language: &str) -> Vec<(String, String)> {
    vec![
        ("accept".to_string(), "*/*".to_string()),
        ("accept-language".to_string(), accept_language.to_string()),
        (
            "accept-encoding".to_string(),
            "gzip, deflate, br, zstd".to_string(),
        ),
        ("content-type".to_string(), REQ_CONTENT_TYPE.to_string()),
        ("origin".to_string(), SENTINEL_ORIGIN.to_string()),
        ("referer".to_string(), frame_referer()),
        ("sec-fetch-dest".to_string(), "empty".to_string()),
        ("sec-fetch-mode".to_string(), "cors".to_string()),
        ("sec-fetch-site".to_string(), "same-origin".to_string()),
    ]
}

// ─────────────────────────── JSON 组装 ───────────────────────────

/// `json.dumps(pairs, separators=(",", ":"))`：**保持给定键序**、无空格。
///
/// 字符串转义复用 [`crate::token::json_string`]（等价于 `ensure_ascii=False`）。
/// 之所以不用 `serde_json::Value`：它按键名字典序输出，`p/t/c/id/flow` 会变成
/// `c/flow/id/p/t`，与 Python 逐字节对不上。
pub fn compact_json(pairs: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(64);
    out.push('{');
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_string(key));
        out.push(':');
        out.push_str(&json_string(value));
    }
    out.push('}');
    out
}

/// `openai-sentinel-token` 头的载荷：
/// `{"p":<enforcement>,"t":<turnstile>,"c":<challenge.token>,"id":<device_id>,"flow":<flow>}`。
pub fn token_payload_json(
    enforcement: &str,
    t: &str,
    c: &str,
    device_id: &str,
    flow: &str,
) -> String {
    compact_json(&[
        ("p", enforcement),
        ("t", t),
        ("c", c),
        ("id", device_id),
        ("flow", flow),
    ])
}

/// `openai-sentinel-so-token` 头的载荷：
/// `{"so":<blob>,"c":<challenge.token>,"id":<device_id>,"flow":<flow>}`。
pub fn so_payload_json(so: &str, c: &str, device_id: &str, flow: &str) -> String {
    compact_json(&[("so", so), ("c", c), ("id", device_id), ("flow", flow)])
}

// ─────────────────────────── /sentinel/req ───────────────────────────

/// 一次 `/sentinel/req` 的请求：`{"p":<requirements token>,"id":<device id>,"flow":<flow>}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRequest {
    /// requirements token（同时是 dx 程序的 XOR key）。
    pub p: String,
    /// 设备 id（`oai-device-id` / `did`）。
    pub device_id: String,
    pub flow: String,
}

impl ChallengeRequest {
    pub fn new(
        p: impl Into<String>,
        device_id: impl Into<String>,
        flow: impl Into<String>,
    ) -> Self {
        Self {
            p: p.into(),
            device_id: device_id.into(),
            flow: flow.into(),
        }
    }

    /// 紧凑 JSON 正文（Python 的 `separators=(",",":")`，键序 `p,id,flow`）。
    pub fn body_text(&self) -> String {
        compact_json(&[
            ("p", &self.p),
            ("id", &self.device_id),
            ("flow", &self.flow),
        ])
    }

    /// 可直接交给 [`super::http::Client`] 的请求描述（离线可断言）。
    pub fn spec(&self, accept_language: &str) -> http::RequestSpec {
        http::RequestSpec::post_raw(
            "sentinel.req",
            SENTINEL_REQ_URL,
            Some(request_headers(accept_language)),
            REQ_CONTENT_TYPE,
            self.body_text(),
        )
    }
}

// ─────────────────────────── challenge ───────────────────────────

/// `/sentinel/req` 的响应（Python 侧就是那个 dict）。
#[derive(Debug, Clone)]
pub struct Challenge {
    raw: JsonValue,
}

impl Challenge {
    /// 从响应正文解析；必须是 JSON 对象（对齐 Python 的 `不是 JSON 对象` 报错）。
    pub fn from_body(body: &str) -> Result<Self> {
        let raw: JsonValue = serde_json::from_str(body)
            .with_context(|| format!("sentinel challenge 不是合法 JSON: {}", snippet(body)))?;
        Self::from_json(raw)
    }

    pub fn from_json(raw: JsonValue) -> Result<Self> {
        if !raw.is_object() {
            bail!("sentinel challenge 响应不是 JSON 对象");
        }
        Ok(Self { raw })
    }

    /// 从 sample 文件那种 `{"challenge": {...}, ...}` 结构里取 challenge。
    ///
    /// 兼容三种形态：整个 blob 就是 challenge / `/challenge` / `/sentinel`。
    pub fn from_blob(blob: &JsonValue) -> Result<Self> {
        let candidate = blob
            .get("challenge")
            .or_else(|| blob.get("sentinel"))
            .unwrap_or(blob);
        Self::from_json(candidate.clone())
    }

    pub fn raw(&self) -> &JsonValue {
        &self.raw
    }

    /// `c` 值：`challenge.token`（Python `str(challenge.get("token") or "")`）。
    pub fn c_value(&self) -> String {
        str_field(&self.raw, "token")
    }

    /// turnstile dx 程序（base64(XOR(JSON, p))）；缺失时返回 `None`。
    pub fn turnstile_dx(&self) -> Option<&str> {
        self.raw
            .pointer("/turnstile/dx")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// `proofofwork` 块（交给 [`crate::token::enforcement_token`]）。
    pub fn proofofwork(&self) -> Option<&JsonValue> {
        self.raw.get("proofofwork")
    }

    /// `so.required`（Python 的 `bool((challenge.get("so") or {}).get("required"))`）。
    pub fn so_required(&self) -> bool {
        truthy(self.raw.pointer("/so/required"))
    }

    /// SO collector 程序（`so.collector_dx`）。
    pub fn collector_dx(&self) -> Option<&str> {
        self.raw
            .pointer("/so/collector_dx")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// SO snapshot 程序（`so.snapshot_dx`）。
    pub fn snapshot_dx(&self) -> Option<&str> {
        self.raw
            .pointer("/so/snapshot_dx")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    pub fn persona(&self) -> String {
        str_field(&self.raw, "persona")
    }

    pub fn expire_after(&self) -> Option<i64> {
        self.raw.get("expire_after").and_then(|v| v.as_i64())
    }
}

/// `str(value or "")`（Python 真值语义）。
fn str_field(raw: &JsonValue, key: &str) -> String {
    match raw.get(key) {
        None | Some(JsonValue::Null) => String::new(),
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Bool(b)) => b.to_string(),
        Some(JsonValue::Number(n)) => n.to_string(),
        Some(_) => String::new(),
    }
}

/// Python `bool(x)`。
fn truthy(value: Option<&JsonValue>) -> bool {
    match value {
        None | Some(JsonValue::Null) => false,
        Some(JsonValue::Bool(b)) => *b,
        Some(JsonValue::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Some(JsonValue::String(s)) => !s.is_empty(),
        Some(JsonValue::Array(a)) => !a.is_empty(),
        Some(JsonValue::Object(o)) => !o.is_empty(),
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

// ─────────────────────────── 传输抽象 ───────────────────────────

/// 把 [`ChallengeRequest`] 变成 [`Challenge`] 的传输层。
///
/// 生产实现是 [`HttpTransport`]；单测/上层可直接注入闭包（本 trait 对所有
/// `Fn(&ChallengeRequest) -> Result<Challenge>` 有 blanket impl）。
pub trait ChallengeTransport: Send + Sync {
    fn fetch(&self, request: &ChallengeRequest) -> Result<Challenge>;
}

impl<F> ChallengeTransport for F
where
    F: Fn(&ChallengeRequest) -> Result<Challenge> + Send + Sync,
{
    fn fetch(&self, request: &ChallengeRequest) -> Result<Challenge> {
        self(request)
    }
}

/// 生产传输：`POST https://sentinel.openai.com/backend-api/sentinel/req`。
pub struct HttpTransport {
    client: Arc<http::Client>,
    accept_language: String,
}

impl HttpTransport {
    pub fn new(client: Arc<http::Client>, accept_language: impl Into<String>) -> Self {
        Self {
            client,
            accept_language: accept_language.into(),
        }
    }
}

impl ChallengeTransport for HttpTransport {
    fn fetch(&self, request: &ChallengeRequest) -> Result<Challenge> {
        let spec = request.spec(&self.accept_language);
        let client = Arc::clone(&self.client);

        // 同步 trait + 异步客户端：起一个短命线程，给它自己的 current-thread runtime。
        // 这样不会嵌套 `block_on` 到调用方的 runtime 里（那会 panic），也不要求
        // 调用方是 multi-thread runtime。
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("sentinel-req".to_string())
            .spawn(move || {
                let outcome = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(client.execute(&spec)),
                    Err(err) => Err(anyhow!("创建 sentinel/req runtime 失败: {err}")),
                };
                let _ = tx.send(outcome);
            })
            .context("启动 sentinel/req 线程失败")?;

        let response = rx
            .recv()
            .context("sentinel/req 线程无响应（发送失败）")?
            .context("sentinel/req 请求失败")?;

        if !response.is_success() {
            bail!(
                "sentinel/req HTTP {}: {}",
                response.status,
                snippet(&response.body)
            );
        }
        Challenge::from_body(&response.body)
    }
}

// ─────────────────────────── PoW / VM 引擎 ───────────────────────────

/// SO token 生成结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoMint {
    /// so 模块就绪，产出了 so blob。
    Ready(String),
    /// so 模块尚未落地（当前是桩）：携带原因，调用方应降级并告警。
    NotReady(String),
    /// 没有 so 依赖（`collector_dx` 为空）。
    Skipped,
}

impl SoMint {
    pub fn is_ready(&self) -> bool {
        matches!(self, SoMint::Ready(blob) if !blob.is_empty())
    }

    /// 产出的 blob（仅 `Ready` 且非空时）。
    pub fn blob(&self) -> Option<&str> {
        match self {
            SoMint::Ready(blob) if !blob.is_empty() => Some(blob.as_str()),
            _ => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            SoMint::NotReady(reason) => Some(reason.as_str()),
            SoMint::Ready(_) | SoMint::Skipped => None,
        }
    }
}

/// `t` / `so` 的本地计算引擎（纯 CPU，不联网）。
///
/// 抽成 trait 是为了让单测能断言"调用顺序 + 入参"，不用真跑 dx 程序。
pub trait MintEngine: Send + Sync {
    /// 跑 `turnstile.dx`，得到 `t`（`p` 同时是 XOR key）。
    fn mint_t(&self, dx: &str, p: &str, profile: &Profile) -> Result<String>;
    /// 跑 SO 的 collector + snapshot，得到 so blob。
    fn mint_so(
        &self,
        collector_dx: &str,
        snapshot_dx: Option<&str>,
        p: &str,
        profile: &Profile,
    ) -> SoMint;
}

/// 生产引擎：[`crate::mint::mint_t`] + [`mint_so_best_effort`]。
#[derive(Debug, Default, Clone, Copy)]
pub struct VmMintEngine;

impl MintEngine for VmMintEngine {
    fn mint_t(&self, dx: &str, p: &str, profile: &Profile) -> Result<String> {
        mint::mint_t(dx, p, profile).map_err(|err| anyhow!("mint_t 失败: {err}"))
    }

    fn mint_so(
        &self,
        collector_dx: &str,
        snapshot_dx: Option<&str>,
        p: &str,
        profile: &Profile,
    ) -> SoMint {
        mint_so_best_effort(collector_dx, snapshot_dx, p, profile)
    }
}

/// SO token 生成：`collector → dispatch_behavior → snapshot` → `so` blob。
///
/// 真实现是 [`crate::so::mint_so_with_rng`]（collector 与 snapshot 共用一个 VM；
/// 生产路径要真人化的事件序列，所以用真随机。要对拍时用 `so::mint_so`，
/// 它把 `random.random()` 固定在 0.5）。
///
/// 失败语义：SO 是"加分项"——`so.required` 的 flow 拿不到 SO token 时主 token 仍
/// 然可用（Python 侧同样只在 blob 非空时才发 `openai-sentinel-so-token` 头），
/// 所以这里把错误降级成 [`SoMint::NotReady`]，由调用方 WARN 后继续。
pub fn mint_so_best_effort(
    collector_dx: &str,
    snapshot_dx: Option<&str>,
    p: &str,
    profile: &Profile,
) -> SoMint {
    if collector_dx.trim().is_empty() {
        return SoMint::Skipped;
    }
    let snapshot = snapshot_dx.unwrap_or("");
    let mut rng = Rng::system();
    match crate::so::mint_so_with_rng(collector_dx, snapshot, p, profile, &mut rng) {
        Ok(blob) => SoMint::Ready(blob),
        Err(err) => SoMint::NotReady(format!("mint_so 失败: {err}")),
    }
}

// ─────────────────────────── token 源 ───────────────────────────

/// 真实 token 源：持有 profile + 传输 + 本地引擎，一次 [`SentinelTokenSource::token`]
/// 走完整条 sentinel 链。
pub struct SentinelSource {
    profile: Profile,
    transport: Arc<dyn ChallengeTransport>,
    engine: Arc<dyn MintEngine>,
    accept_language: String,
}

impl SentinelSource {
    /// 用生产引擎（`mint_t` + SO 桩）构造。
    pub fn new(profile: Profile, transport: Arc<dyn ChallengeTransport>) -> Self {
        Self::with_engine(profile, transport, Arc::new(VmMintEngine))
    }

    /// 注入自定义引擎（单测 / 后续接真 `mint_so`）。
    pub fn with_engine(
        profile: Profile,
        transport: Arc<dyn ChallengeTransport>,
        engine: Arc<dyn MintEngine>,
    ) -> Self {
        let accept_language = profile.language.clone();
        Self {
            profile,
            transport,
            engine,
            accept_language,
        }
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// 覆盖 `accept-language`（默认取 profile.language）。
    pub fn with_accept_language(mut self, accept_language: impl Into<String>) -> Self {
        self.accept_language = accept_language.into();
        self
    }

    /// 这一步的请求描述（dry-run 计划用；**不发请求**）。
    pub fn challenge_spec(&self, device_id: &str, flow: &str) -> http::RequestSpec {
        ChallengeRequest::new("<requirements-token>", device_id, flow).spec(&self.accept_language)
    }
}

impl SentinelTokenSource for SentinelSource {
    fn token(&self, flow: &str, device_id: &str) -> Result<SentinelToken> {
        if flow.trim().is_empty() {
            bail!("sentinel flow 不能为空");
        }
        // 设备 id 缺省时本地铸一个（Python `str(device_id or uuid4())`）。
        let did = if device_id.trim().is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            device_id.trim().to_string()
        };
        // sdk.js 的 p[14] 是 instance sid（独立随机 UUID），不是 device_id。
        let sid = uuid::Uuid::new_v4().to_string();
        // Python 的 PoW seed 也是 `str(uuid.uuid4())`。
        let seed = uuid::Uuid::new_v4().to_string();
        let mut ctx = TokenCtx::system();

        // 1) requirements token（PoW difficulty=0）—— 同时是 dx 的 XOR key。
        let request_p = requirements_token(&self.profile, &sid, &seed, &mut ctx)
            .map_err(|err| anyhow!("requirements_token 失败: {err}"))?;
        debug!(
            "[sentinel] requirements ok len={} flow={flow}",
            request_p.len()
        );

        // 2) POST /backend-api/sentinel/req → challenge
        let challenge = self
            .transport
            .fetch(&ChallengeRequest::new(
                request_p.clone(),
                did.clone(),
                flow.to_string(),
            ))
            .with_context(|| format!("获取 sentinel challenge 失败（flow={flow}）"))?;

        // 3) enforcement（p）：有 proofofwork 就跑 PoW，否则回退 requirements token。
        let enforcement = enforcement_token(challenge.raw(), &self.profile, &sid, &mut ctx)
            .map_err(|err| anyhow!("enforcement_token 失败: {err}"))?
            .unwrap_or_else(|| request_p.clone());

        let c_value = challenge.c_value();
        if c_value.is_empty() {
            bail!("sentinel challenge 缺少 token（c 值为空，flow={flow}）");
        }

        // 4) turnstile t：dx 程序用 request_p 当 XOR key。
        let t_value = match challenge.turnstile_dx() {
            Some(dx) => {
                let t = self.engine.mint_t(dx, &request_p, &self.profile)?;
                if t.is_empty() {
                    bail!("dx VM 未产出 t（flow={flow}）");
                }
                debug!("[sentinel] turnstile ok len={}", t.len());
                t
            }
            None => String::new(),
        };

        let token = token_payload_json(&enforcement, &t_value, &c_value, &did, flow);

        // 5) SO token（仅当 challenge 要求）。桩就绪前降级为"不带 SO 头"。
        let mut so_token = None;
        if challenge.so_required() {
            match challenge.collector_dx() {
                Some(collector) => {
                    match self.engine.mint_so(
                        collector,
                        challenge.snapshot_dx(),
                        &request_p,
                        &self.profile,
                    ) {
                        SoMint::Ready(blob) if !blob.is_empty() => {
                            info!("[sentinel] so ok len={} flow={flow}", blob.len());
                            so_token =
                                Some(so_payload_json(&blob, &c_value, &did, flow));
                        }
                        SoMint::Ready(_) => {
                            warn!("[sentinel] so 程序跑完但 blob 为空（flow={flow}），不带 SO 头");
                        }
                        SoMint::NotReady(reason) => {
                            warn!("[sentinel] flow={flow} 需要 SO token，但{reason}");
                        }
                        SoMint::Skipped => {
                            debug!("[sentinel] flow={flow} 的 SO 程序为空，跳过");
                        }
                    }
                }
                None => warn!(
                    "[sentinel] challenge.so.required=true 但没有 collector_dx（flow={flow}），跳过 SO"
                ),
            }
        }

        info!(
            "[sentinel] token ok flow={flow} p={} t={} so={}",
            enforcement.len(),
            t_value.len(),
            so_token.as_ref().map(|s| s.len()).unwrap_or(0)
        );
        Ok(SentinelToken { token, so_token })
    }
}

// ─────────────────────────── 闭包源 ───────────────────────────

/// 把一个闭包包成 [`SentinelTokenSource`]（上层注入 / 单测替身用）。
#[derive(Clone)]
pub struct ClosureSource {
    f: Arc<dyn Fn(&str, &str) -> Result<SentinelToken> + Send + Sync>,
}

impl ClosureSource {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, &str) -> Result<SentinelToken> + Send + Sync + 'static,
    {
        Self { f: Arc::new(f) }
    }
}

impl SentinelTokenSource for ClosureSource {
    fn token(&self, flow: &str, device_id: &str) -> Result<SentinelToken> {
        (self.f)(flow, device_id)
    }
}

// ─────────────────────────── profile / 工厂 ───────────────────────────

/// 用**设备指纹**造 profile：token 里的 `profile` 块与 HTTP 头完全同源。
///
/// UA / 屏幕 / 语言 / 平台 / vendor / 硬件 / dpr / 时区 全部取
/// [`DeviceFingerprint::profile_options`]，不存在"头说 Windows、token 说 MacIntel"
/// 这种自相矛盾。
pub fn profile_from_fp(fp: &DeviceFingerprint) -> Profile {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    Profile::new(&fp.profile_options(), now_ms, &mut Rng::system())
}

/// 显式 UA / 语言覆盖（无指纹）时的兜底：只从 UA + `accept-language` 推 profile。
///
/// 其余字段走 [`ProfileOptions::default`]（Python 侧同样如此），所以随机指纹路径
/// 一律用 [`profile_from_fp`]，不要走这里。
pub fn profile_for(user_agent: &str, accept_language: &str) -> Profile {
    let language = accept_language
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let options = ProfileOptions {
        user_agent: Some(user_agent.to_string()),
        lang: if language.is_empty() {
            None
        } else {
            Some(language.to_string())
        },
        languages: if accept_language.trim().is_empty() {
            None
        } else {
            Some(accept_language.to_string())
        },
        ..ProfileOptions::default()
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    Profile::new(&options, now_ms, &mut Rng::system())
}

/// 生产环境用的 token 源：自带一个独立 cookie jar 的 HTTP client。
///
/// sentinel 端点不依赖 auth cookie，所以与注册链的 client 分开是安全的；
/// 这样 [`SentinelTokenSource::token`] 保持同步签名，编排层不用改。
///
/// `fp = Some(..)` 时：profile 走 [`profile_from_fp`]，TLS/HTTP2 emulation 也切到
/// 指纹对应的 Chrome 档位（与 UA 的版本号一致）；`None` 时保持旧行为。
pub fn live_source(
    user_agent: &str,
    accept_language: &str,
    proxy: Option<&str>,
    fp: Option<&DeviceFingerprint>,
) -> Result<SentinelSource> {
    let emulation = fp.and_then(|fp| http::parse_emulation(&fp.emulation));
    let client = Arc::new(
        http::Client::build_with_emulation(
            user_agent,
            proxy,
            http::RetryPolicy::default(),
            emulation,
        )
        .context("构建 sentinel HTTP client 失败")?,
    );
    let profile = match fp {
        Some(fp) => profile_from_fp(fp),
        None => profile_for(user_agent, accept_language),
    };
    let transport = Arc::new(HttpTransport::new(client, accept_language.to_string()));
    Ok(SentinelSource::new(profile, transport).with_accept_language(accept_language.to_string()))
}

// ─────────────────────────── 单测（模块内小工具） ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_json_keeps_order_and_escapes() {
        let text = compact_json(&[("p", "a\"b"), ("t", "t1")]);
        assert_eq!(text, r#"{"p":"a\"b","t":"t1"}"#);
        assert!(text.find("\"p\"").unwrap() < text.find("\"t\"").unwrap());
    }

    #[test]
    fn challenge_accessors() {
        let raw = serde_json::json!({
            "token": "c-1",
            "turnstile": {"dx": "DX"},
            "so": {"required": true, "collector_dx": "COL", "snapshot_dx": "SNAP"},
            "proofofwork": {"required": false}
        });
        let challenge = Challenge::from_json(raw).unwrap();
        assert_eq!(challenge.c_value(), "c-1");
        assert_eq!(challenge.turnstile_dx(), Some("DX"));
        assert!(challenge.so_required());
        assert_eq!(challenge.collector_dx(), Some("COL"));
        assert_eq!(challenge.snapshot_dx(), Some("SNAP"));
        assert!(Challenge::from_json(serde_json::json!([])).is_err());
    }
}
