//! sentinel token 源 + OAuth 段的离线单测。
//!
//! **全程不联网**：
//! * `SentinelSource` 的传输层注入闭包（返回事先写好的 challenge）；
//! * `MintEngine` 注入记录器（不跑真 dx VM）；
//! * `auth` / `plan` 那部分只断言请求构造与响应解析。
//!
//! 重点验证两件事：
//! 1. 链路顺序：requirements → `/sentinel/req` → `mint_t` →（so.required 才）`mint_so`；
//! 2. `SentinelToken` 的 JSON 结构与 Python `separators=(",",":")` 的键序逐字一致。

use std::sync::{Arc, Mutex};

use sentinel_rs::flow::auth::{self, AuthRequestBuilder};
use sentinel_rs::flow::http::Method;
use sentinel_rs::flow::sentinel::{
    self, Challenge, ChallengeRequest, ChallengeTransport, MintEngine, SentinelSource, SoMint,
};
use sentinel_rs::flow::{
    self, RegisterConfig, RegisterIdentity, SentinelToken, SentinelTokenSource,
};
use sentinel_rs::token::{Profile, ProfileOptions, Rng};

// ─────────────────────────── 测试替身 ───────────────────────────

/// 记录所有发生过的步骤（跨线程共享）。
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<String>>>);

impl Trace {
    fn push(&self, step: impl Into<String>) {
        self.0.lock().unwrap().push(step.into());
    }

    fn steps(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// 假传输：记录 `/sentinel/req` 的入参，返回预置 challenge。
struct RecordingTransport {
    trace: Trace,
    body: String,
}

impl ChallengeTransport for RecordingTransport {
    fn fetch(&self, request: &ChallengeRequest) -> anyhow::Result<Challenge> {
        self.trace.push(format!(
            "req:flow={} id={} body={}",
            request.flow,
            request.device_id,
            request.body_text()
        ));
        Challenge::from_body(&self.body)
    }
}

/// 假引擎：记录 `mint_t` / `mint_so` 的入参，返回固定值。
struct RecordingEngine {
    trace: Trace,
    t: String,
    so: SoMint,
}

impl MintEngine for RecordingEngine {
    fn mint_t(&self, dx: &str, p: &str, _profile: &Profile) -> anyhow::Result<String> {
        self.trace.push(format!("t:dx={dx} p={p}"));
        Ok(self.t.clone())
    }

    fn mint_so(
        &self,
        collector_dx: &str,
        snapshot_dx: Option<&str>,
        p: &str,
        _profile: &Profile,
    ) -> SoMint {
        self.trace.push(format!(
            "so:collector={collector_dx} snapshot={} p={p}",
            snapshot_dx.unwrap_or("<none>")
        ));
        self.so.clone()
    }
}

fn profile() -> Profile {
    Profile::new(
        &ProfileOptions {
            user_agent: Some("UA/test".to_string()),
            lang: Some("en-US".to_string()),
            ..ProfileOptions::default()
        },
        1_793_036_746_210.0,
        &mut Rng::constant(0.5),
    )
}

/// so 必需的 challenge（c / dx / collector / snapshot 齐备）。
fn challenge_with_so() -> String {
    serde_json::json!({
        "token": "c-value-1",
        "turnstile": {"required": true, "dx": "DX-PROG"},
        "proofofwork": {"required": false},
        "so": {"required": true, "collector_dx": "COL-PROG", "snapshot_dx": "SNAP-PROG"}
    })
    .to_string()
}

fn source_with(trace: &Trace, body: &str, so: SoMint) -> SentinelSource {
    SentinelSource::with_engine(
        profile(),
        Arc::new(RecordingTransport {
            trace: trace.clone(),
            body: body.to_string(),
        }),
        Arc::new(RecordingEngine {
            trace: trace.clone(),
            t: "T-VALUE".to_string(),
            so,
        }),
    )
}

// ─────────────────────────── 链路顺序 ───────────────────────────

#[test]
fn sentinel_chain_order_is_requirements_req_then_so() {
    let trace = Trace::default();
    let source = source_with(
        &trace,
        &challenge_with_so(),
        SoMint::Ready("SO-BLOB".into()),
    );

    let token = source.token("email_otp_validate", "device-abc").unwrap();

    let steps = trace.steps();
    assert_eq!(steps.len(), 3, "应恰好三步: {steps:?}");
    assert!(steps[0].starts_with("req:flow=email_otp_validate id=device-abc"));
    assert!(steps[1].starts_with("t:dx=DX-PROG"));
    assert!(steps[2].starts_with("so:collector=COL-PROG snapshot=SNAP-PROG"));

    // 关键不变量：dx 的 XOR key 就是 /sentinel/req 的 p，也就是 requirements token
    let req_body = steps[0].split("body=").nth(1).unwrap();
    let req_json: serde_json::Value = serde_json::from_str(req_body).unwrap();
    let p_in_req = req_json["p"].as_str().unwrap();
    assert!(
        p_in_req.starts_with("gAAAAAC") && p_in_req.ends_with("~S"),
        "requirements token 形态不对: {p_in_req}"
    );
    assert!(
        steps[1].ends_with(&format!("p={p_in_req}")),
        "mint_t 的 key 必须是 requirements token"
    );
    assert!(steps[2].ends_with(&format!("p={p_in_req}")));
    assert!(!token.token.is_empty());
}

#[test]
fn sentinel_token_json_shape_matches_python_payload() {
    let trace = Trace::default();
    let source = source_with(
        &trace,
        &challenge_with_so(),
        SoMint::Ready("SO-BLOB".into()),
    );
    let token = source.token("email_otp_validate", "device-abc").unwrap();

    // ── 主 token：p / t / c / id / flow，顺序固定、无空格 ──
    let parsed: serde_json::Value = serde_json::from_str(&token.token).unwrap();
    assert!(parsed.is_object());
    for key in ["p", "t", "c", "id", "flow"] {
        assert!(parsed.get(key).is_some(), "缺字段 {key}: {}", token.token);
    }
    assert_eq!(parsed["t"], "T-VALUE");
    assert_eq!(parsed["c"], "c-value-1");
    assert_eq!(parsed["id"], "device-abc");
    assert_eq!(parsed["flow"], "email_otp_validate");
    // PoW 不要求 → p 回退 requirements token
    assert!(parsed["p"].as_str().unwrap().starts_with("gAAAAAC"));

    let order: Vec<usize> = ["\"p\"", "\"t\"", "\"c\"", "\"id\"", "\"flow\""]
        .iter()
        .map(|key| token.token.find(key).unwrap())
        .collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted, "键序必须与 Python 一致: {}", token.token);
    assert!(!token.token.contains(' '), "不应有空格: {}", token.token);

    // ── SO token：so / c / id / flow ──
    let so = token
        .so_token
        .expect("so.required=true 且 blob 非空时应带 SO token");
    let parsed_so: serde_json::Value = serde_json::from_str(&so).unwrap();
    assert_eq!(parsed_so["so"], "SO-BLOB");
    assert_eq!(parsed_so["c"], "c-value-1");
    assert_eq!(parsed_so["id"], "device-abc");
    assert_eq!(parsed_so["flow"], "email_otp_validate");
    assert!(so.find("\"so\"").unwrap() < so.find("\"c\"").unwrap());
}

#[test]
fn sentinel_skips_so_when_challenge_does_not_require_it() {
    let trace = Trace::default();
    let body = serde_json::json!({
        "token": "c-2",
        "turnstile": {"dx": "DX"},
        "so": {"required": false}
    })
    .to_string();
    let source = source_with(&trace, &body, SoMint::Ready("SHOULD-NOT-BE-USED".into()));

    let token = source.token("authorize_continue", "did-1").unwrap();
    assert!(token.so_token.is_none(), "so 未要求时不该产出 SO token");
    assert_eq!(
        trace.steps().len(),
        2,
        "只该有 req + t: {:?}",
        trace.steps()
    );
    assert!(trace.steps().iter().all(|step| !step.starts_with("so:")));
}

#[test]
fn sentinel_not_ready_so_still_returns_main_token() {
    // 文档化桩行为：so 依赖未就绪时主 token 照常返回，只是不带 SO 头。
    let trace = Trace::default();
    let source = source_with(
        &trace,
        &challenge_with_so(),
        SoMint::NotReady("TODO(so): 桩".into()),
    );
    let token = source.token("oauth_create_account", "did-2").unwrap();
    assert!(token.so_token.is_none());
    assert!(token.token.contains("\"flow\":\"oauth_create_account\""));
}

#[test]
fn sentinel_rejects_challenge_without_c_value() {
    let trace = Trace::default();
    let body = serde_json::json!({"turnstile": {"dx": "DX"}}).to_string();
    let source = source_with(&trace, &body, SoMint::Skipped);
    let err = source.token("authorize_continue", "did-3").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("token"), "{msg}");
    assert!(msg.contains("challenge"), "{msg}");
}

#[test]
fn sentinel_rejects_empty_flow_and_bad_challenge() {
    let trace = Trace::default();
    let source = source_with(&trace, &challenge_with_so(), SoMint::Skipped);
    assert!(source.token("   ", "did").is_err());

    assert!(Challenge::from_body("not json").is_err());
    assert!(Challenge::from_body("[]").is_err());
    assert!(Challenge::from_body(r#"{"token":"c"}"#).is_ok());
}

#[test]
fn omitted_dx_yields_empty_t() {
    let trace = Trace::default();
    let body = serde_json::json!({"token": "c-3"}).to_string();
    let source = source_with(&trace, &body, SoMint::Skipped);
    let token = source.token("authorize_continue", "did-4").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&token.token).unwrap();
    assert_eq!(parsed["t"], "", "没有 dx 时 t 应为空串（对齐 Python）");
    assert_eq!(trace.steps().len(), 1, "没有 dx 不该跑 VM");
}

#[test]
fn sentinel_req_spec_matches_python_headers_and_body() {
    let request = ChallengeRequest::new("P-TOKEN", "DEV-1", "email_otp");
    let spec = request.spec("en-US,en;q=0.9");

    assert_eq!(spec.method, Method::Post);
    assert_eq!(spec.url, sentinel::SENTINEL_REQ_URL);
    assert_eq!(spec.label, "sentinel.req");
    assert_eq!(
        spec.header("content-type"),
        Some(sentinel::REQ_CONTENT_TYPE),
        "sentinel/req 用 text/plain;charset=UTF-8"
    );
    assert_eq!(spec.header("origin"), Some("https://sentinel.openai.com"));
    assert!(spec
        .header("referer")
        .unwrap()
        .contains("backend-api/sentinel/frame.html?sv="));
    // 原始正文（`RequestSpec::raw`），键序 p,id,flow
    assert_eq!(
        spec.raw().expect("sentinel/req 必须有原始正文"),
        r#"{"p":"P-TOKEN","id":"DEV-1","flow":"email_otp"}"#
    );
    assert!(spec.body.is_none(), "sentinel/req 不走 JSON Value body");
}

// ─────────────────────────── OAuth 段 ───────────────────────────

#[test]
fn oauth_token_exchange_request_and_parse() {
    let params = auth::OAuthParams::default().with_verifier("verifier-1");
    let spec = auth::exchange_code_for_token("CODE 1", &params);

    assert_eq!(spec.method, Method::Post);
    assert_eq!(spec.url, auth::EP_OAUTH_TOKEN);
    assert_eq!(
        spec.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(spec.header("origin"), Some(auth::AUTH_BASE));
    let body = spec.raw().expect("oauth/token 必须是 form 正文");
    assert!(
        body.starts_with("grant_type=authorization_code&client_id="),
        "{body}"
    );
    assert!(body.contains("&code=CODE+1"), "code 需要 form 转义: {body}");
    assert!(
        body.contains("&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Fopenai"),
        "{body}"
    );
    // code_verifier 排在 redirect_uri 之后（对齐 Python 的字段追加顺序）
    assert!(body.ends_with("&code_verifier=verifier-1"), "{body}");

    let parsed = auth::parse_token_exchange(
        200,
        r#"{"access_token":"at-1","id_token":"id-1","refresh_token":"rt-1","expires_in":3600}"#,
    )
    .unwrap();
    assert_eq!(parsed.access_token, "at-1");
    assert_eq!(parsed.refresh_token, "rt-1");
    assert_eq!(parsed.expires_in, Some(3600));

    let err =
        auth::parse_token_exchange(400, r#"{"error":{"message":"invalid_grant"}}"#).unwrap_err();
    assert!(format!("{err:#}").contains("invalid_grant"));
    assert!(auth::parse_token_exchange(200, r#"{"id_token":"x"}"#).is_err());
}

#[test]
fn workspace_select_and_session() {
    let builder = AuthRequestBuilder::new("UA/1", "en-US", "device-1");
    let spec = builder.select_workspace("ws-123");
    assert_eq!(spec.method, Method::Post);
    assert_eq!(spec.url, auth::EP_WORKSPACE_SELECT);
    assert_eq!(spec.body.as_ref().unwrap()["workspace_id"], "ws-123");
    assert!(
        spec.header(auth::HDR_SENTINEL).is_none(),
        "workspace/select 不带 sentinel 头"
    );

    let parsed = auth::parse_workspace_select(
        200,
        r#"{"continue_url":"https://chatgpt.com/api/auth/callback/openai?code=abc"}"#,
    )
    .unwrap();
    assert!(parsed.continue_url.contains("code=abc"));
    assert!(auth::parse_workspace_select(500, "{}").is_err());

    let session =
        auth::parse_chat_session(r#"{"accessToken":"at-2","sessionToken":"st-2"}"#).unwrap();
    assert_eq!(session.access_token, "at-2");
    assert_eq!(session.session_token, "st-2");
    let session = auth::parse_chat_session(r#"{"access_token":"at-3"}"#).unwrap();
    assert_eq!(session.access_token, "at-3");

    let spec = builder.chat_session();
    assert_eq!(spec.url, auth::EP_CHAT_SESSION);
    assert_eq!(spec.method, Method::Get);
}

#[test]
fn callback_code_and_workspace_id_extraction() {
    let callback = "https://chatgpt.com/api/auth/callback/openai?code=abc%2Bdef&state=xyz";
    assert!(auth::is_callback_url(callback));
    assert_eq!(auth::callback_code(callback).as_deref(), Some("abc+def"));
    assert_eq!(
        auth::callback_code("https://chatgpt.com/api/auth/callback/openai"),
        None
    );

    // 相对路径归一
    assert_eq!(
        auth::absolute_url("/create-account/password", auth::AUTH_BASE),
        "https://auth.openai.com/create-account/password"
    );
    assert_eq!(
        auth::absolute_url("https://chatgpt.com/", auth::AUTH_BASE),
        "https://chatgpt.com/"
    );
    assert_eq!(auth::absolute_url("", auth::AUTH_BASE), "");

    // cookie → workspace id（base64url(JSON)）
    let payload = r#"{"workspace_id":"11111111-2222-3333-4444-555555555555"}"#;
    let segment = base64url(payload);
    let cookie = format!("oai-did=abc; oai-client-auth-session={segment}.sig; other=1");
    assert_eq!(
        auth::workspace_id_from_cookie_header(&cookie).as_deref(),
        Some("11111111-2222-3333-4444-555555555555")
    );
    assert!(auth::workspace_id_from_cookie_header("oai-did=abc").is_none());

    // workspaces[0].id 兜底
    let payload = r#"{"workspaces":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}"#;
    let cookie = format!("oai-client-auth-session={}", base64url(payload));
    assert_eq!(
        auth::workspace_id_from_cookie_header(&cookie).as_deref(),
        Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );

    // HTML 兜底
    let html = r#"<script>window.x = {"workspaces":[{"id":"99999999-8888-7777-6666-555555555555"}]}</script>"#;
    assert_eq!(
        auth::workspace_id_from_html(html).as_deref(),
        Some("99999999-8888-7777-6666-555555555555")
    );
    assert!(auth::workspace_id_from_html("<html>nothing</html>").is_none());

    assert_eq!(auth::urlencode("a b+c/d"), "a+b%2Bc%2Fd");
    assert_eq!(auth::url_decode("a+b%2Bc"), "a b+c");
    assert_eq!(auth::url_decode("100%"), "100%");
}

fn base64url(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text.as_bytes())
}

// ─────────────────────────── 计划 / 编排 ───────────────────────────

#[test]
fn dry_run_plan_contains_real_sentinel_and_oauth_steps() {
    let cfg = RegisterConfig::default();
    let identity = RegisterIdentity::placeholder();
    let steps = flow::build_plan_steps(&cfg, &identity);

    let describes: Vec<String> = steps.iter().map(|step| step.describe()).collect();
    let joined = describes.join("\n");

    // 每个 flow 的 sentinel 三件套
    for flow_name in [
        "authorize_continue",
        "username_password_create",
        "email_otp",
        "email_otp_validate",
        "oauth_create_account",
    ] {
        assert!(
            joined.contains(&format!("flow={flow_name}")),
            "计划缺 flow={flow_name}"
        );
    }
    assert!(joined.contains("sentinel.requirements"));
    assert!(joined.contains("sentinel.turnstile"));
    assert_eq!(
        describes
            .iter()
            .filter(|line| line.contains("https://sentinel.openai.com/backend-api/sentinel/req"))
            .count(),
        5,
        "5 个 flow 各有一次 /sentinel/req"
    );

    // OAuth 段
    assert!(joined.contains(auth::EP_WORKSPACE_SELECT));
    assert!(joined.contains(auth::EP_CHAT_SESSION));
    assert!(joined.contains(auth::EP_OAUTH_TOKEN));
    assert!(joined.contains("auth.follow_redirect"));

    // 落库
    assert!(joined.contains("store.save_account"));

    // 旧 API 只保留 HTTP 步骤
    let http_specs = flow::build_plan(&cfg, &identity);
    assert_eq!(
        http_specs.len(),
        steps.iter().filter(|s| s.is_http()).count()
    );
    assert_eq!(http_specs[0].label, "email.health");
}

#[test]
fn dry_run_register_prints_sentinel_steps_without_network() {
    let cfg = RegisterConfig::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let source = sentinel::ClosureSource::new(|flow, _did| {
        Ok(SentinelToken {
            token: format!("mock-{flow}"),
            so_token: None,
        })
    });
    let outcome = runtime
        .block_on(flow::register_once_with(&cfg, &source))
        .unwrap();

    assert!(outcome.dry_run);
    let joined = outcome.plan.join("\n");
    assert!(joined.contains("sentinel.req"), "{joined}");
    assert!(
        joined.contains("POST https://sentinel.openai.com/backend-api/sentinel/req"),
        "{joined}"
    );
    // 每个 flow 都出现在计划里（含 create_account 之后的那段 OAuth）
    assert!(joined.contains("flow=oauth_create_account"), "{joined}");
    assert!(joined.contains("auth.oauth_token"), "{joined}");
    // 计划里写明 /sentinel/req 的请求体形状，但 token 是占位（不是真值）
    assert!(joined.contains("POST 体"), "{joined}");
    assert!(
        joined.contains("gAAAAAC…~S"),
        "requirements token 应显示为截断占位: {joined}"
    );
    assert!(joined.contains("sentinel.requirements"), "{joined}");
}

#[test]
fn closure_source_is_used_by_orchestrator_in_order() {
    // 用记录闭包验证 live 链路会按顺序请求 sentinel（这里走 dry-run=false 之前的
    // 前置校验会挡邮箱，所以只验证 trait 层顺序 + 归零行为）。
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = calls.clone();
    let source = sentinel::ClosureSource::new(move |flow: &str, did: &str| {
        sink.lock().unwrap().push(format!("{flow}/{did}"));
        Ok(SentinelToken {
            token: "t".into(),
            so_token: None,
        })
    });
    source.token("authorize_continue", "d1").unwrap();
    source.token("email_otp", "d1").unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            "authorize_continue/d1".to_string(),
            "email_otp/d1".to_string()
        ]
    );
}

/// SO 生成的真实现（`so::mint_so_with_rng`）：坏程序降级不 panic，空程序跳过。
#[test]
fn so_mint_degrades_gracefully_on_bad_program() {
    let profile = profile();
    let result = sentinel::mint_so_best_effort("not-a-program", Some("also-bad"), "p", &profile);
    assert!(matches!(result, SoMint::NotReady(_)), "{result:?}");
    let reason = result.reason().unwrap();
    assert!(reason.contains("mint_so 失败"), "{reason}");
    assert!(result.blob().is_none());
    assert!(!result.is_ready());

    assert!(matches!(
        sentinel::mint_so_best_effort("", None, "p", &profile),
        SoMint::Skipped
    ));
}

/// 端到端：用 `sample_challenge.json` 里真实的 `so.collector_dx` + `snapshot_dx`
/// 跑一遍 SO 生成，产出非空 `so` blob（纯本地 VM，不联网）。
#[test]
fn so_mint_produces_blob_from_sample_challenge() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_challenge.json");
    let text = std::fs::read_to_string(&path).expect("读取 sample_challenge.json");
    let blob: serde_json::Value =
        serde_json::from_str(&text).expect("sample_challenge.json 应是 JSON");

    let p = blob
        .get("p")
        .and_then(|v| v.as_str())
        .expect("文件里应有 p");
    let challenge = Challenge::from_blob(&blob).expect("文件里应有 challenge");
    assert!(challenge.so_required(), "该 challenge 应要求 SO token");
    let collector = challenge.collector_dx().expect("应有 collector_dx");
    assert!(challenge.snapshot_dx().is_some(), "应有 snapshot_dx");

    let fp = blob.get("fp").cloned().unwrap_or(serde_json::Value::Null);
    let mut rng = Rng::constant(0.5);
    let profile = if fp.get("user_agent").is_some() {
        Profile::from_fingerprint(&fp, 1_793_036_746_210.0, &mut rng).expect("fp → profile")
    } else {
        profile()
    };

    let result = sentinel::mint_so_best_effort(collector, challenge.snapshot_dx(), p, &profile);
    let so = result
        .blob()
        .unwrap_or_else(|| panic!("SO 应产出 blob: {result:?}"));
    assert!(so.len() > 100, "so 太短: {}", so.len());
    assert!(
        so.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c)),
        "so 应是 base64 形态"
    );

    // so 载荷的键序与 Python 一致
    let payload = sentinel::so_payload_json(so, "c-1", "did-1", "email_otp_validate");
    assert!(payload.starts_with("{\"so\":"));
    assert!(payload.ends_with(",\"c\":\"c-1\",\"id\":\"did-1\",\"flow\":\"email_otp_validate\"}"));
}
