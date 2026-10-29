//! 注册流程骨架（离线可编译 / 可单测 / 默认不联网）。
//!
//! 分层（每层都先产出纯数据，HTTP 只负责发送，方便离线单测）：
//!   * [`sentinel`] —— sentinel token 源（requirements → /sentinel/req → t → so）
//!   * [`auth`]  —— auth.openai.com 的请求构造 + 响应解析（含 workspace/oauth 段）
//!   * [`email`] —— 通用邮箱取码 API 客户端（纯 HTTP 契约，见该模块文档）
//!   * [`otp`]   —— 从邮件正文 / 取码页 HTML 提取 6 位验证码
//!   * [`twofa`] —— TOTP（RFC 6238）+ mfa enroll/activate 请求构造
//!   * [`store`] —— rusqlite 建表 + 账号落库
//!   * [`http`]  —— 传输层（wreq/BoringSSL，Chrome TLS+HTTP2 指纹；cookie jar / 重试 / 代理）
//!
//! ### 安全边界
//! [`RegisterConfig::dry_run`] 默认 `true`：dry-run 只构造并打印请求计划，
//! **不发任何网络请求、不注册、不发邮件、不写真实凭证**。只有显式设置
//! `SENTINEL_LIVE_REGISTER=1` 才会走真实链路。
//!
//! ### 顺序（对齐 `协议/auth_flow.py`）
//! `warmup（GET chatgpt.com/api/auth/csrf，种 oai-did）→ signin/openai（拿带
//! login_hint 的 authorize URL）→ auth_oauth_init（浏览器头 GET authorize + 跟随
//! 重定向，建立会话 state）→ 落地 URL 判定 signup/existing → GET
//! create-account/password → user/register（设密码）→ GET email-otp/send → 邮箱取码
//! → email-otp/validate → create_account → workspace/select → 跟随重定向拿 callback
//! code → chatgpt session → oauth/token 换 access_token →（可选）mfa enroll/activate
//! → 落库`
//!
//! ⚠️ **不再**用 `POST authorize/continue` 建立会话：Python 侧那个 POST 现在 0 次
//! 调用，邮箱靠 signin 的 `login_hint` 透传进 authorize URL。裸头（只发
//! Accept/Referer/UA）实测 409=3/6，补齐 client hints + 整组 `Sec-Fetch-*` 后 409=0。
//!
//! 每个需要 sentinel 的步骤前都会插一段 [`sentinel`] 生成（requirements →
//! `/backend-api/sentinel/req` → `mint_t` →（必要时）`mint_so`）。

pub mod auth;
pub mod authorize;
pub mod email;
pub mod http;
pub mod otp;
pub mod sentinel;
pub mod store;
pub mod twofa;

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// 环境变量前缀：`SENTINEL_*`。
pub const ENV_PREFIX: &str = "SENTINEL_";

pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/145.0.0.0 Safari/537.36";

// ─────────────────────────── 配置 ───────────────────────────

/// 注册流程配置：全部来自环境变量 / `.env`。
///
/// | 变量 | 含义 | 缺省 |
/// |---|---|---|
/// | `SENTINEL_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` | 代理（`host:port` 或 `http://user:pass@host:port`） | 直连 |
/// | `REG_MAIL_API_BASE_URL` | 邮箱 API 基地址（必填，`https://`） | 未配置 → 不能 `--live` |
/// | `REG_MAIL_API_TOKEN` | 邮箱 API bearer token（可选） | 空 → 不发鉴权头 |
/// | `REG_MAIL_ALLOW_INSECURE` | `1` 时放行回环 `http://`（本地自建 / mock） | `0` |
/// | `SENTINEL_ENABLE_2FA` | 注册后是否绑 TOTP | `false` |
/// | `SENTINEL_COUNT` / `REGISTER_COUNT` | 批量数量 | `1` |
/// | `SENTINEL_DB_PATH` | SQLite 路径 | `data/sentinel-rs.db` |
/// | `OTP_MAX_WAIT` / `OTP_POLL_INTERVAL` | 取码等待上限 / 轮询间隔（秒） | `180` / `3` |
/// | `SENTINEL_LIVE_REGISTER` | `1` 才真的联网注册 | `0`（dry-run） |
/// | `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE` | 指纹相关 | 内置 Chrome UA / `en-US,en;q=0.9` |
#[derive(Debug, Clone)]
pub struct RegisterConfig {
    pub proxy: Option<String>,
    pub email_api: Option<email::EmailApiConfig>,
    pub enable_2fa: bool,
    pub count: usize,
    pub db_path: PathBuf,
    pub otp_max_wait_secs: u64,
    pub otp_poll_interval_secs: u64,
    pub user_agent: String,
    pub accept_language: String,
    pub dry_run: bool,
    /// 只跑 warmup → signin → authorize init（不领邮箱、不注册），验证会话建立。
    pub preflight: bool,
}

impl Default for RegisterConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            email_api: None,
            enable_2fa: false,
            count: 1,
            db_path: PathBuf::from("data/sentinel-rs.db"),
            otp_max_wait_secs: 180,
            otp_poll_interval_secs: 3,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
            dry_run: true,
            preflight: false,
        }
    }
}

impl RegisterConfig {
    /// 从进程环境变量读取（`.env` 由 `main` 里的 `dotenvy::dotenv()` 提前载入）。
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 可注入的读取器：单测里用闭包喂假值，不污染进程环境。
    pub fn from_lookup<F>(lookup: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |key: &str| {
            lookup(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let count_raw = get("SENTINEL_COUNT").or_else(|| get("REGISTER_COUNT"));
        let count = match count_raw {
            Some(raw) => raw
                .parse::<usize>()
                .with_context(|| format!("SENTINEL_COUNT 解析失败（需要正整数）: {raw:?}"))?,
            None => 1,
        };
        if count == 0 {
            bail!("SENTINEL_COUNT 必须 >= 1（当前 {count}）");
        }

        let otp_max_wait_secs = parse_u64(&get, "OTP_MAX_WAIT", 180)?;
        let otp_poll_interval_secs = parse_u64(&get, "OTP_POLL_INTERVAL", 3)?.max(1);

        let proxy = get("SENTINEL_PROXY")
            .or_else(|| get("HTTPS_PROXY"))
            .or_else(|| get("https_proxy"))
            .or_else(|| get("ALL_PROXY"))
            .or_else(|| get("all_proxy"));
        if let Some(raw) = &proxy {
            http::normalize_proxy_url(raw).with_context(|| {
                format!("代理配置无法解析: {raw:?}（期望 host:port 或 scheme://host:port）")
            })?;
        }

        let email_api = email::EmailApiConfig::from_lookup(&lookup)?;

        let dry_run = match get("SENTINEL_LIVE_REGISTER") {
            Some(v) => !matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
            None => true,
        };

        Ok(Self {
            proxy,
            email_api,
            enable_2fa: matches!(
                get("SENTINEL_ENABLE_2FA")
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            ),
            count,
            db_path: get("SENTINEL_DB_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("data/sentinel-rs.db")),
            otp_max_wait_secs,
            otp_poll_interval_secs,
            user_agent: get("SENTINEL_USER_AGENT")
                .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string()),
            accept_language: get("SENTINEL_ACCEPT_LANGUAGE")
                .unwrap_or_else(|| "en-US,en;q=0.9".to_string()),
            dry_run,
            preflight: false,
        })
    }

    /// 真实链路必须有的东西；dry-run 不做强制（沙箱里也能跑 `register -n 1`）。
    pub fn require_live_prerequisites(&self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }
        if self.email_api.is_none() {
            bail!(
                "缺少邮箱 API 配置：请设置 REG_MAIL_API_BASE_URL（必填，https://），\
                 需要鉴权时再设 REG_MAIL_API_TOKEN；本地自建 / mock 服务另需 \
                 REG_MAIL_ALLOW_INSECURE=1"
            );
        }
        Ok(())
    }
}

fn parse_u64(get: &dyn Fn(&str) -> Option<String>, key: &str, default: u64) -> Result<u64> {
    match get(key) {
        Some(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("{key} 解析失败（需要非负整数）: {raw:?}")),
        None => Ok(default),
    }
}

// ─────────────────────────── sentinel token 源 ───────────────────────────

/// sentinel 一次性的主 token + SO token。
#[derive(Debug, Clone, Default)]
pub struct SentinelToken {
    pub token: String,
    pub so_token: Option<String>,
}

/// 抽象 sentinel token 生成器，隔离尚未就绪的 `mint` 模块。
/// Sentinel token 来源。
///
/// 要求 `Send + Sync`：注册流程会被放进多线程 runtime 并发执行，token 源必须
/// 能跨线程共享，否则 future 不是 `Send`，`tokio::spawn` 用不了。
pub trait SentinelTokenSource: Send + Sync {
    fn token(&self, flow: &str, device_id: &str) -> Result<SentinelToken>;
}

/// 占位实现：`sentinel_rs::mint::mint_t` 由 mint 代理实现中。
///
/// 就绪后新增一个 impl 即可接上，注册链路本身不用改。
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingSentinelSource;

impl SentinelTokenSource for MissingSentinelSource {
    fn token(&self, flow: &str, _device_id: &str) -> Result<SentinelToken> {
        bail!(
            "TODO(mint): sentinel token 生成器尚未就绪，无法为 flow={flow} 取 token \
             （等 sentinel_rs::mint::mint_t 落地后实现 SentinelTokenSource）"
        )
    }
}

// ─────────────────────────── 结果 / 编排 ───────────────────────────

/// 一次注册的结果（dry-run 时只有 `plan` 有内容）。
#[derive(Debug, Clone, Default)]
pub struct RegistrationOutcome {
    pub dry_run: bool,
    pub email: String,
    pub password: String,
    pub access_token: Option<String>,
    pub totp_secret: Option<String>,
    pub account_id: Option<i64>,
    /// dry-run 打印的请求计划（method + url + label）。
    pub plan: Vec<String>,
}

/// 一次注册里的随机身份（邮箱来自邮箱 API，密码/设备 id 本地生成）。
#[derive(Debug, Clone)]
pub struct RegisterIdentity {
    pub email: String,
    pub password: String,
    pub device_id: String,
}

impl RegisterIdentity {
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: auth::random_password(16),
            device_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// dry-run 用的占位身份：不碰邮箱 API。
    pub fn placeholder() -> Self {
        let tag: String = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(8)
            .collect();
        Self::new(format!("dryrun+{tag}@example.invalid"))
    }
}

/// 注册一次。dry-run 只产出请求计划，不联网。
///
/// 真实模式（`SENTINEL_LIVE_REGISTER=1`）用 [`sentinel::live_source`] 造真实 token 源；
/// dry-run 用 [`MissingSentinelSource`]——它一被调用就报错，而 dry-run 根本不会调它。
pub async fn register_once(cfg: &RegisterConfig) -> Result<RegistrationOutcome> {
    if cfg.dry_run {
        return register_once_with(cfg, &MissingSentinelSource).await;
    }
    let source = sentinel::live_source(&cfg.user_agent, &cfg.accept_language, cfg.proxy.as_deref())
        .context("初始化 sentinel token 源失败")?;
    register_once_with(cfg, &source).await
}

/// 可注入 sentinel token 源的版本（便于接 mint，也便于测试）。
pub async fn register_once_with(
    cfg: &RegisterConfig,
    sentinel: &dyn SentinelTokenSource,
) -> Result<RegistrationOutcome> {
    cfg.require_live_prerequisites()?;

    if cfg.dry_run {
        let identity = RegisterIdentity::placeholder();
        let steps = build_plan_steps(cfg, &identity);
        let http_count = steps.iter().filter(|step| step.is_http()).count();
        info!(
            "dry-run：仅构造请求，不会联网（共 {} 步，其中 {http_count} 个 HTTP 请求）",
            steps.len()
        );
        return Ok(RegistrationOutcome {
            dry_run: true,
            email: identity.email,
            password: identity.password,
            plan: steps.iter().map(|step| step.describe()).collect(),
            ..Default::default()
        });
    }

    live_register(cfg, sentinel).await
}

/// 只验证 authorize 会话是否建得起来：warmup → signin → authorize init。
///
/// **不领邮箱、不注册、不发码**，所以可以随便跑：signin 用保留域名
/// `preflight+<tag>@example.com` 当 `login_hint`（Python 侧同类探测里
/// `400 invalid_username` 被视为"会话正常，只是域名被拒"）。
/// 存在的意义：链路上任何一步坏掉都会在下游 `user/register` 变成
/// 409 invalid_state，而那时邮箱已经花掉了 —— 先在这里用 0 成本把状态摸清。
pub async fn preflight_authorize(cfg: &RegisterConfig) -> Result<Vec<String>> {
    use auth::AuthRequestBuilder;

    let http = http::Client::build(
        &cfg.user_agent,
        cfg.proxy.as_deref(),
        http::RetryPolicy::default(),
    )?;

    let probe = AuthRequestBuilder::new(&cfg.user_agent, &cfg.accept_language, "");
    let warm = authorize::warmup(&http, &probe).await?;

    let tag: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect();
    let email = format!("preflight+{tag}@example.com");
    let builder = AuthRequestBuilder::new(&cfg.user_agent, &cfg.accept_language, &warm.device_id);

    let auth_url = authorize::fetch_authorize_url(
        &http,
        &builder,
        &email,
        &warm.csrf_token,
        &warm.device_id,
    )
    .await?;
    let init = authorize::auth_oauth_init(&http, &builder, &auth_url, &warm.device_id).await?;

    let landing = init
        .landing_url
        .split('?')
        .next()
        .unwrap_or(&init.landing_url)
        .to_string();
    let verdict = auth::classify_landing(&init.landing_url, auth::Intent::Signup);

    Ok(vec![
        format!("warmup          : ok（第 {} 次）oai-did={}…", warm.attempts, &warm.device_id[..warm.device_id.len().min(8)]),
        format!("authorize hops  : {}", init.hops.join(" → ")),
        format!("authorize 落地  : {landing}"),
        format!("判定            : {verdict:?}"),
        format!("最终状态码      : {}", init.final_status),
    ])
}

/// 真实链路（沙箱内不会执行；`SENTINEL_LIVE_REGISTER=1` 才会进入）。
async fn live_register(
    cfg: &RegisterConfig,
    sentinel: &dyn SentinelTokenSource,
) -> Result<RegistrationOutcome> {
    use auth::{AuthRequestBuilder, Intent};

    cfg.require_live_prerequisites()?;
    let email_api = cfg
        .email_api
        .as_ref()
        .context("缺少邮箱 API 配置（REG_MAIL_API_BASE_URL）")?;

    let http = http::Client::build(
        &cfg.user_agent,
        cfg.proxy.as_deref(),
        http::RetryPolicy::default(),
    )?;
    let mail = email::MailApiClient::new(&http, email_api.clone());

    // 0) warmup：GET chatgpt.com/api/auth/csrf —— 种 oai-did。
    //    Python run_register 的第一件事，且必须在领邮箱之前拦掉：没有 oai-did 的会话
    //    在 signin 阶段拿不到 auth.openai.com 的 authorize URL，后续必 409，别为注定
    //    失败的轮次浪费一个邮箱。
    let probe = AuthRequestBuilder::new(&cfg.user_agent, &cfg.accept_language, "");
    let warm = authorize::warmup(&http, &probe).await?;

    // 1) 建/领邮箱
    let mailbox = mail
        .create_mailbox(None, None)
        .await
        .context("创建邮箱失败")?;
    let mut identity = RegisterIdentity::new(mailbox.email.clone());
    // oai-did 必须用 warmup 种下的那个（Python `_resolve_device_id`：cookie 优先，
    // 凭空 uuid4 服务端不认这个会话 —— 那正是 409 invalid_state 的上游根因）
    identity.device_id = warm.device_id.clone();
    let builder =
        AuthRequestBuilder::new(&cfg.user_agent, &cfg.accept_language, &identity.device_id);

    // 2) signin → authorize URL。邮箱靠 login_hint 透传进去；
    //    Python 当前**不再 POST authorize/continue**（那个 POST 0 次调用）。
    let auth_url = authorize::fetch_authorize_url(
        &http,
        &builder,
        &identity.email,
        &warm.csrf_token,
        &identity.device_id,
    )
    .await?;

    // 3) authorize init：整套浏览器头 GET + 跟随重定向 → 建立后续步骤要用的 state
    let init = authorize::auth_oauth_init(&http, &builder, &auth_url, &identity.device_id).await?;
    info!(
        "[authorize] 状态码序列: {}",
        init.hops.join(" → ")
    );

    // 4) 判定新账号 / 已有账号：**只看 authorize 落地 URL**
    //    （Python `_classify_authorize_landing`；authorize/continue 的 page.type 已失效）
    let mut verdict = auth::classify_landing(&init.landing_url, Intent::Signup);
    if verdict == auth::Landing::Unknown {
        // 落地 URL 判不出时才回退到已废弃的 authorize/continue 探测（Python 同样兜底）
        warn!("[signup] authorize 落地 URL 无法判定，回退 authorize/continue 探测");
        let st = sentinel.token("authorize_continue", &identity.device_id)?;
        let spec = builder.authorize_continue(&identity.email, &st.token, "signup");
        let resp = http.execute(&spec).await?;
        if resp.status >= 400 {
            warn!(
                "authorize/continue 探测返回 {}: {}",
                resp.status,
                http::body_string(&resp).chars().take(300).collect::<String>()
            );
        } else {
            let landing = auth::parse_authorize_continue(&http::body_string(&resp))?;
            if let Some(page) = landing.page.as_ref() {
                info!("authorize/continue page.type = {}", page.kind);
            }
            verdict = auth::classify_landing(&landing.continue_url, Intent::Signup);
        }
    }
    match verdict {
        auth::Landing::New => info!(
            "[signup] 判定为新账号（落地 {}）",
            init.landing_url.split('?').next().unwrap_or("")
        ),
        auth::Landing::Existing => bail!(
            "authorize 落地判定为已有账号（{}），本轮不进入注册密码流程",
            init.landing_url.split('?').next().unwrap_or("")
        ),
        auth::Landing::Unknown => warn!("[signup] 仍判不出新/已有账号，保守按新注册继续"),
    }

    // 5) GET create-account/password —— 整页导航建立"设密码"页状态
    //    （真机是点「Continue with password」后的 navigatedWithinDocument，纯协议用
    //    一次文档 GET 等价；这次导航之后要铸新的 document-navigation-id）
    let page = builder.create_account_password_page();
    let resp = http.execute(&page).await?;
    info!(
        "[4/10] create-account/password 页面 status={}（Location: {}）",
        resp.status,
        resp.header("location").map(str::trim).unwrap_or("-")
    );
    builder.new_document_navigation();

    // 6) user/register 设密码 —— 服务端账号在这一步真正建立
    let st = sentinel.token(sentinel::FLOW_USERNAME_PASSWORD_CREATE, &identity.device_id)?;
    let spec = builder.register_password(&identity.email, &identity.password, &st);
    let resp = http.execute(&spec).await?;
    if resp.status != 200 {
        bail!(
            "user/register 失败: HTTP {} body={}（会话 state 没建立时这里必 409 invalid_state）",
            resp.status,
            http::body_string(&resp).chars().take(600).collect::<String>()
        );
    }
    info!("[5/10] 密码注册成功（账号已在服务端建立）");

    // ⚠️ 立刻落库：密码只活在内存里，后面发码/验证码/create_account 任何一步挂掉，
    //    这个号就永久进不去了（Python 在 POST 200 之后同样立刻回调落盘）。
    let store = store::Store::open(&cfg.db_path)?;
    store.init()?;
    let pending = store::Account {
        email: identity.email.clone(),
        password: identity.password.clone(),
        cookies: merge_cookie_headers(&[
            http.cookie_header_for(auth::AUTH_BASE),
            http.cookie_header_for(auth::CHATGPT_BASE),
        ]),
        status: "pending_otp".to_string(),
        created_at: store::now_ts(),
        updated_at: store::now_ts(),
        ..Default::default()
    };
    store.save_account(&pending)?;

    // 7) 发码（POST user/register 成功后服务端切到 email_otp_send 页，必须重新发码）
    builder.new_document_navigation();
    let st = sentinel.token(sentinel::FLOW_EMAIL_OTP, &identity.device_id)?;
    let spec = builder.send_otp(&st);
    let resp = http.execute(&spec).await?;
    if resp.status != 200 {
        bail!(
            "发送 OTP 失败: HTTP {} body={}",
            resp.status,
            http::body_string(&resp).chars().take(600).collect::<String>()
        );
    }
    info!("[6/10] OTP 已发送");

    // 6) 取码
    let code = mail
        .poll_otp(
            &mailbox.code_url,
            cfg.otp_max_wait_secs,
            cfg.otp_poll_interval_secs,
        )
        .await
        .context("等待邮箱验证码失败")?;
    info!("已取得邮箱验证码");

    // 8) 验证 OTP（该 flow 服务端要求 SO token）
    let st = sentinel.token(sentinel::FLOW_EMAIL_OTP_VALIDATE, &identity.device_id)?;
    let spec = builder.verify_otp(&code, &st);
    let resp = http.execute(&spec).await?;
    if resp.status != 200 {
        bail!(
            "email-otp/validate 失败: HTTP {} body={}",
            resp.status,
            http::body_string(&resp).chars().take(600).collect::<String>()
        );
    }
    info!("[7/10] OTP 验证成功");

    // 9) 创建账户（姓名/生日；该 flow 服务端要求 SO token）
    let st = sentinel.token(sentinel::FLOW_CREATE_ACCOUNT, &identity.device_id)?;
    let spec = builder.create_account(&st);
    let resp = http.execute(&spec).await?;
    if resp.status != 200 {
        bail!(
            "create_account 失败: HTTP {} body={}",
            resp.status,
            http::body_string(&resp).chars().take(600).collect::<String>()
        );
    }
    let created = auth::parse_create_account(&http::body_string(&resp))?;
    info!(
        "[8/10] create_account ok（continue_url={}）",
        if created.continue_url.is_empty() { "空" } else { "有" }
    );
    if created.continue_url.is_empty() {
        warn!("create_account 未返回 continue_url，改用 cookie 里的 workspace id 自行 select");
    }

    // 9) workspace select → 跟随重定向 → callback code → session → token 交换
    //    （对齐 auth_flow.create_account() 之后的 9/10 步；尽力而为，失败不丢号）
    let handoff = complete_oauth(&http, &builder, &created.continue_url).await;

    // 10) 可选 2FA：enroll → 用 TOTP 激活（现在有真 access_token 了）
    let mut totp_secret = None;
    if cfg.enable_2fa {
        if handoff.access_token.is_empty() {
            warn!("2FA：未拿到 access_token（oauth 交换失败），跳过 enroll/activate");
        } else {
            let access_token = handoff.access_token.as_str();
            let st = sentinel.token(sentinel::FLOW_CREATE_ACCOUNT, &identity.device_id)?;
            let spec = twofa::enroll_spec(&builder, access_token, &st);
            let resp = http.execute(&spec).await?;
            let enrolled = twofa::parse_enroll(&http::body_string(&resp))?;
            let code = twofa::totp_now(&enrolled.secret)?;
            let st = sentinel.token(sentinel::FLOW_CREATE_ACCOUNT, &identity.device_id)?;
            let spec = twofa::activate_spec(&builder, access_token, &code, &enrolled.session_id, &st);
            http.execute(&spec).await?;
            totp_secret = Some(enrolled.secret);
        }
    }

    // 10) 落库（access_token / cookies 都来自上一步；账号在 user/register 时已写过
    //     pending_otp，这里按 email upsert 更新成最终状态）
    let account = store::Account {
        email: identity.email.clone(),
        password: identity.password.clone(),
        access_token: handoff.access_token.clone(),
        totp_secret: totp_secret.clone().unwrap_or_default(),
        cookies: merge_cookie_headers(&[
            http.cookie_header_for(auth::AUTH_BASE),
            http.cookie_header_for(auth::CHATGPT_BASE),
        ]),
        status: if handoff.access_token.is_empty() {
            "registered_no_token".to_string()
        } else {
            "registered".to_string()
        },
        created_at: store::now_ts(),
        updated_at: store::now_ts(),
    };
    let account_id = store.save_account(&account)?;

    Ok(RegistrationOutcome {
        dry_run: false,
        email: identity.email,
        password: identity.password,
        access_token: Some(handoff.access_token).filter(|token| !token.is_empty()),
        totp_secret,
        account_id: Some(account_id),
        plan: Vec::new(),
    })
}

/// 合并多个 `Cookie:` 头字符串（去空、去重名）。
pub(crate) fn merge_cookie_headers(headers: &[String]) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    for header in headers {
        for part in header.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let name = part.split_once('=').map(|(n, _)| n.trim()).unwrap_or(part);
            if seen.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                continue;
            }
            seen.push(name.to_string());
            out.push(part.to_string());
        }
    }
    out.join("; ")
}

// ─────────────────── create_account 之后（workspace / callback / oauth）───────────────────

/// `create_account` 之后的收尾：workspace/select → 跟随重定向拿 callback →
/// 消费 callback 种 session cookie → `chatgpt/api/auth/session` → `oauth/token`。
///
/// 全部**尽力而为**：任何一步失败只打 WARN，账号本身已经建好了，不能因为拿不到
/// access_token 就把号丢掉（Python 侧这里会抛，故意放宽）。
async fn complete_oauth(
    http: &http::Client,
    builder: &auth::AuthRequestBuilder,
    continue_url: &str,
) -> auth::OAuthHandoff {
    let mut out = auth::OAuthHandoff::default();
    let mut next = auth::absolute_url(continue_url, auth::AUTH_BASE);

    // 1) 没有 continue_url、或落地在 /workspace 页面 → 用 workspace id 主动 select
    if next.is_empty() || auth::is_workspace_page(&next) {
        let workspace_id = auth::workspace_id_from_url(&next).or_else(|| {
            auth::workspace_id_from_cookie_header(&http.cookie_header_for(auth::AUTH_BASE))
        });
        match workspace_id {
            Some(workspace_id) => {
                info!("workspace/select: workspace_id={workspace_id}");
                let spec = builder.select_workspace(&workspace_id);
                match http.execute(&spec).await {
                    Ok(resp) => match auth::parse_workspace_select(resp.status, &resp.body) {
                        Ok(parsed) if !parsed.continue_url.is_empty() => {
                            next = auth::absolute_url(&parsed.continue_url, auth::AUTH_BASE);
                            debug!("workspace/select → {next}");
                        }
                        Ok(_) => warn!("workspace/select 未返回 continue_url"),
                        Err(err) => warn!("workspace/select 解析失败: {err:#}"),
                    },
                    Err(err) => warn!("workspace/select 请求失败: {err:#}"),
                }
            }
            None => warn!(
                "没拿到 workspace id（continue_url 为空，且 cookie 里没有 oai-client-auth-session）"
            ),
        }
    }
    out.continue_url = next.clone();
    if next.is_empty() {
        warn!("OAuth 段跳过：没有可用的 continue_url");
        return out;
    }

    // 2) 逐跳跟随，直到捕获 NextAuth callback（带 code）
    match follow_redirect_chain(http, builder, &next).await {
        Ok((callback, final_url)) => {
            if callback.is_empty() {
                warn!("重定向链未捕获 callback code（final={final_url}）");
            } else {
                out.callback_url = callback.clone();
                out.code = auth::callback_code(&callback).unwrap_or_default();
                info!("捕获 callback（未消费）: code={}", !out.code.is_empty());
                // 3) 主动消费 callback：让 chatgpt.com 种 __Secure-next-auth.session-token
                let spec = builder.navigation_from(&callback, &format!("{}/", auth::AUTH_BASE));
                let _ = http.execute(&spec).await;
            }
        }
        Err(err) => warn!("跟随重定向链失败: {err:#}"),
    }

    // 4) chatgpt 会话（accessToken 的权威来源）
    let spec = builder.chat_session();
    match http.execute(&spec).await {
        Ok(resp) => match auth::parse_chat_session(&resp.body) {
            Ok(session) => {
                if !session.access_token.is_empty() {
                    out.access_token = session.access_token;
                }
                if !session.session_token.is_empty() {
                    out.session_token = session.session_token;
                }
                debug!(
                    "chatgpt session: at={} st={}",
                    !out.access_token.is_empty(),
                    !out.session_token.is_empty()
                );
            }
            Err(err) => warn!("chatgpt session 解析失败: {err:#}"),
        },
        Err(err) => warn!("chatgpt session 请求失败: {err:#}"),
    }
    if out.session_token.is_empty() {
        out.session_token = auth::cookie_value(
            &http.cookie_header_for(auth::CHATGPT_BASE),
            "__Secure-next-auth.session-token",
        )
        .unwrap_or_default();
    }

    // 5) code → access_token / refresh_token（尽力；与 session 互为兜底）
    //
    // ⚠️ 正常流程走到这里时，access_token 已经在第 4 步由 chatgpt session 拿到；
    // 此时再打 oauth/token 必然 401 invalid_client —— 我们这条链路没有 PKCE
    // code_verifier，且该 code 已被 NextAuth 消费。这种情况直接跳过，不再刷 WARN。
    if !out.access_token.is_empty() {
        debug!("已有 session access_token，跳过 oauth/token 交换（预期行为）");
    } else if out.code.is_empty() {
        warn!("既没有 callback code 也没有 session AT，无法获取 access_token");
    } else {
        let params = auth::OAuthParams::default();
        let spec = auth::exchange_code_for_token(&out.code, &params);
        match http.execute(&spec).await {
            Ok(resp) => match auth::parse_token_exchange(resp.status, &resp.body) {
                Ok(token) => {
                    if out.access_token.is_empty() {
                        out.access_token = token.access_token;
                    }
                    out.refresh_token = token.refresh_token;
                    info!(
                        "oauth/token ok: at={} rt={}",
                        !out.access_token.is_empty(),
                        !out.refresh_token.is_empty()
                    );
                }
                Err(err) => warn!("oauth/token 交换失败: {err:#}"),
            },
            Err(err) => warn!("oauth/token 请求失败: {err:#}"),
        }
    }
    out
}

/// 逐跳 GET 跟随 3xx，返回 `(callback_url, final_url)`。
///
/// 对齐 Python `follow_redirect_chain()` 的关键约定：**不主动 GET callback**，
/// 只记录它（`code` 被消费前留给后面的交换）。`/workspace` 页面（200）会主动
/// 调 `workspace/select` 换下一跳。
async fn follow_redirect_chain(
    http: &http::Client,
    builder: &auth::AuthRequestBuilder,
    start: &str,
) -> Result<(String, String)> {

    // 逐跳 GET 跟随 3xx，返回 `(callback_url, final_url)`。
    const MAX_HOPS: usize = 12;
    let mut current = start.to_string();
    let mut referer = format!("{}/", auth::AUTH_BASE);

    for hop in 1..=MAX_HOPS {
        if auth::is_callback_url(&current) && auth::callback_code(&current).is_some() {
            return Ok((current.clone(), current));
        }
        let spec = builder.navigation_from(&current, &referer);
        let resp = http
            .execute(&spec)
            .await
            .with_context(|| format!("第 {hop} 跳请求失败: {current}"))?;
        let status = resp.status;

        if (300..400).contains(&status) {
            let location = resp.header("location").map(str::trim).unwrap_or("");
            if location.is_empty() {
                debug!("第 {hop} 跳 {status} 但没有 Location，结束");
                break;
            }
            let next = auth::absolute_url(location, &current);
            referer = current.clone();
            if auth::is_callback_url(&next) && auth::callback_code(&next).is_some() {
                return Ok((next.clone(), next));
            }
            debug!("第 {hop} 跳 {status} → {next}");
            current = next;
            continue;
        }

        if status == 200 && auth::is_workspace_page(&current) {
            let workspace_id =
                auth::workspace_id_from_cookie_header(&http.cookie_header_for(auth::AUTH_BASE))
                    .or_else(|| auth::workspace_id_from_html(&resp.body));
            if let Some(workspace_id) = workspace_id {
                let spec = builder.select_workspace(&workspace_id);
                if let Ok(selected) = http.execute(&spec).await {
                    if let Ok(parsed) =
                        auth::parse_workspace_select(selected.status, &selected.body)
                    {
                        if !parsed.continue_url.is_empty() {
                            referer = current.clone();
                            current = auth::absolute_url(&parsed.continue_url, &current);
                            info!("workspace 页面 → workspace/select → {current}");
                            continue;
                        }
                    }
                }
            }
        }

        debug!("第 {hop} 跳 status={status}，终止");
        break;
    }
    Ok((String::new(), current))
}

// ─────────────────────────── dry-run 计划 ───────────────────────────

/// dry-run 计划里的一步：要么是 HTTP 请求，要么是**本地计算**（PoW / dx VM / 落库）。
///
/// 之所以要区分：sentinel 链里真正的"重活"（requirements 的 PoW、`mint_t` 的 VM）
/// 不发请求，但它们是计划里最关键的步骤——只打印 HTTP 会让人以为少了 sentinel。
#[derive(Debug, Clone)]
pub enum PlanStep {
    /// 一个待发送的 HTTP 请求。
    Http(http::RequestSpec),
    /// 本地计算 / 本地动作（不联网）。
    Local {
        label: &'static str,
        detail: String,
    },
}

impl PlanStep {
    pub fn local(label: &'static str, detail: impl Into<String>) -> Self {
        PlanStep::Local {
            label,
            detail: detail.into(),
        }
    }

    pub fn is_http(&self) -> bool {
        matches!(self, PlanStep::Http(_))
    }

    pub fn label(&self) -> &'static str {
        match self {
            PlanStep::Http(spec) => spec.label,
            PlanStep::Local { label, .. } => label,
        }
    }

    /// 一行可读描述（`register -n 1` 打印用）。
    pub fn describe(&self) -> String {
        match self {
            PlanStep::Http(spec) => spec.describe(),
            PlanStep::Local { label, detail } => format!("[本地] {label}: {detail}"),
        }
    }

    /// 带头的详细描述（HTTP 步骤会打印脱敏后的头 + body）。
    pub fn describe_with_headers(&self) -> String {
        match self {
            PlanStep::Http(spec) => spec.describe_with_headers(),
            PlanStep::Local { .. } => self.describe(),
        }
    }

    pub fn as_http(&self) -> Option<&http::RequestSpec> {
        match self {
            PlanStep::Http(spec) => Some(spec),
            PlanStep::Local { .. } => None,
        }
    }
}

/// 一个 sentinel 生成块：requirements（本地）→ `/sentinel/req`（HTTP）→ t/so（本地）。
///
/// `sentinel.req` 的 `p` 在 dry-run 里是占位符（真值要跑 PoW，且属于一次性凭证）。
fn sentinel_steps(flow: &str, device_id: &str, accept_language: &str) -> Vec<PlanStep> {
    vec![
        PlanStep::local(
            "sentinel.requirements",
            format!(
                "requirements_token(profile, sid) → gAAAAAC…~S（PoW difficulty=0，flow={flow}，\
                 id={device_id}；随后 POST 体 = {{\"p\":<该 token>,\"id\":<id>,\"flow\":\"{flow}\"}}）"
            ),
        ),
        PlanStep::Http(sentinel::ChallengeRequest::new("<requirements-token>", device_id, flow).spec(
            accept_language,
        )),
        PlanStep::local(
            "sentinel.turnstile",
            format!(
                "mint_t(turnstile.dx, p=requirements token) → t；若 challenge.so.required 再 \
                 mint_so(collector_dx, snapshot_dx) → so（so 依赖 TODO，flow={flow}）"
            ),
        ),
    ]
}

/// 构造 dry-run 的**完整**计划（含 sentinel 本地步骤，纯函数，不发请求）。
pub fn build_plan_steps(cfg: &RegisterConfig, identity: &RegisterIdentity) -> Vec<PlanStep> {
    use auth::AuthRequestBuilder;

    let builder =
        AuthRequestBuilder::new(&cfg.user_agent, &cfg.accept_language, &identity.device_id);
    let st = SentinelToken {
        token: "<sentinel-token>".to_string(),
        so_token: Some("<sentinel-so-token>".to_string()),
    };
    let did = identity.device_id.as_str();
    let lang = cfg.accept_language.as_str();

    let mut steps: Vec<PlanStep> = Vec::new();

    // 邮箱：有配置就用真实端点，没有就写占位，方便看清楚缺哪一段。
    match &cfg.email_api {
        Some(api) => {
            let mail = email::MailApiClient::new_offline(api.clone());
            steps.push(PlanStep::Http(mail.health_spec()));
            steps.push(PlanStep::Http(mail.create_mailbox_spec(None, None)));
            steps.push(PlanStep::Http(
                mail.inbox_spec("<code_url from create_mailbox response>"),
            ));
        }
        None => {
            steps.push(PlanStep::Http(http::RequestSpec::get(
                "email.health",
                "<未配置邮箱 API：设置 REG_MAIL_API_BASE_URL>/health",
            )));
            steps.push(PlanStep::Http(http::RequestSpec::post_json(
                "email.create_mailbox",
                "<未配置邮箱 API：POST {REG_MAIL_API_BASE_URL}/mailboxes>",
                None,
                None,
            )));
        }
    }

    // 1.5) 建立 authorize 会话状态的三步（缺任一步，下游 user/register 必 409）
    steps.push(PlanStep::Http(builder.warmup_spec()));
    steps.push(PlanStep::Http(builder.signin_openai_spec(
        &identity.email,
        "<csrfToken from warmup>",
        did,
        builder.auth_session_logging_id(),
    )));
    steps.push(PlanStep::Http(
        builder.authorize_init_spec("<authorize URL from signin（已补 login_hint/ccaps）>"),
    ));

    // 2) authorize/continue（**仅**落地 URL 判不出时的兜底探测；Python 主链路 0 次调用）
    steps.extend(sentinel_steps(
        sentinel::FLOW_AUTHORIZE_CONTINUE,
        did,
        lang,
    ));
    steps.push(PlanStep::Http(builder.authorize_continue(
        &identity.email,
        &st.token,
        "signup",
    )));

    // 3) 打开 create-account/password 文档
    steps.push(PlanStep::Http(
        builder.navigation(auth::PAGE_CREATE_ACCOUNT_PASSWORD),
    ));

    // 4) 设密码（sentinel: username_password_create）
    steps.extend(sentinel_steps(
        sentinel::FLOW_USERNAME_PASSWORD_CREATE,
        did,
        lang,
    ));
    steps.push(PlanStep::Http(builder.register_password(
        &identity.email,
        &identity.password,
        &st,
    )));

    // 5) 发码（sentinel: email_otp）
    steps.extend(sentinel_steps(sentinel::FLOW_EMAIL_OTP, did, lang));
    steps.push(PlanStep::Http(builder.send_otp(&st)));

    // 6) 取码（轮询邮箱，纯本地等待）
    steps.push(PlanStep::local(
        "email.wait_otp",
        format!(
            "轮询邮箱取 6 位验证码（最多 {}s，间隔 {}s）",
            cfg.otp_max_wait_secs, cfg.otp_poll_interval_secs
        ),
    ));

    // 7) 验证 OTP（sentinel: email_otp_validate，服务端要求 SO token）
    steps.extend(sentinel_steps(
        sentinel::FLOW_EMAIL_OTP_VALIDATE,
        did,
        lang,
    ));
    steps.push(PlanStep::Http(builder.verify_otp("<6 位邮箱验证码>", &st)));

    // 8) 创建账户（sentinel: oauth_create_account，要求 SO token）
    steps.extend(sentinel_steps(
        sentinel::FLOW_CREATE_ACCOUNT,
        did,
        lang,
    ));
    steps.push(PlanStep::Http(builder.create_account(&st)));

    // 9) workspace select → 跟随重定向 → callback → session → oauth/token
    steps.push(PlanStep::local(
        "auth.workspace",
        "取 create_account.continue_url；为空或落在 /workspace 时用 cookie \
         oai-client-auth-session（或页面 HTML）里的 workspace_id 调 workspace/select",
    ));
    steps.push(PlanStep::Http(
        builder.select_workspace("<workspace_id>"),
    ));
    steps.push(PlanStep::local(
        "auth.follow_redirect",
        "从 continue_url 逐跳 GET（最多 12 跳），捕获 /api/auth/callback/openai?code=…（不主动消费）",
    ));
    steps.push(PlanStep::Http(builder.navigation_from(
        "<continue_url from create_account>",
        &format!("{}/", auth::AUTH_BASE),
    )));
    steps.push(PlanStep::Http(builder.navigation_from(
        "<callback_url with code>",
        &format!("{}/", auth::AUTH_BASE),
    )));
    steps.push(PlanStep::Http(builder.chat_session()));
    steps.push(PlanStep::Http(auth::exchange_code_for_token(
        "<code from callback>",
        &auth::OAuthParams::default(),
    )));
    steps.push(PlanStep::local(
        "auth.access_token",
        "解析 oauth/token 的 access_token / id_token / refresh_token（缺失时回退 chatgpt session）",
    ));

    // 10) 可选 2FA
    if cfg.enable_2fa {
        steps.push(PlanStep::Http(twofa::mfa_info_spec(
            &builder,
            "<access_token>",
            &st,
        )));
        steps.push(PlanStep::Http(twofa::enroll_spec(
            &builder,
            "<access_token>",
            &st,
        )));
        steps.push(PlanStep::Local {
            label: "2fa.totp",
            detail: "用 enroll 返回的 secret 本地算 TOTP（RFC 6238）".to_string(),
        });
        steps.push(PlanStep::Http(twofa::activate_spec(
            &builder,
            "<access_token>",
            "<TOTP>",
            "<session_id>",
            &st,
        )));
    }

    // 11) 落库
    steps.push(PlanStep::local(
        "store.save_account",
        format!("写入 SQLite（{}）", cfg.db_path.display()),
    ));

    steps
}

/// 构造 dry-run 的 **HTTP** 请求计划（纯函数，不发请求）。
///
/// 只保留 HTTP 步骤（历史 API，`tests/flow_tests.rs` 依赖它）；要看含 sentinel
/// 本地步骤的完整计划请用 [`build_plan_steps`]。
pub fn build_plan(cfg: &RegisterConfig, identity: &RegisterIdentity) -> Vec<http::RequestSpec> {
    build_plan_steps(cfg, identity)
        .into_iter()
        .filter_map(|step| match step {
            PlanStep::Http(spec) => Some(spec),
            PlanStep::Local { .. } => None,
        })
        .collect()
}
