//! 注册流程骨架的离线单测：OTP 提取 / TOTP 已知向量 / SQLite / 配置解析 / 请求构造。
//!
//! 全部不联网：HTTP 层只测纯逻辑（重试策略、代理规范化、请求描述），
//! 编排层只测 dry-run 计划构造。

use sentinel_rs::flow::auth::{self, AuthRequestBuilder, Intent, Landing};
use sentinel_rs::flow::email::{self, EmailApiConfig};
use sentinel_rs::flow::http::{self, Method, RequestSpec, RetryPolicy};
use sentinel_rs::flow::otp;
use sentinel_rs::flow::store::{self, Account, Store};
use sentinel_rs::flow::twofa;
use sentinel_rs::flow::{self, RegisterConfig, RegisterIdentity, SentinelToken, SentinelTokenSource};
use std::collections::{HashMap, HashSet};

fn lookup_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |key: &str| map.get(key).cloned()
}

// ─────────────────────────── OTP 提取 ───────────────────────────

#[test]
fn otp_extracts_six_digits_with_boundaries() {
    assert_eq!(
        otp::extract_otp("Your code is 778324, expires in 10 minutes"),
        Some("778324".to_string())
    );
    // 前后紧邻数字不算 6 位码（对齐 Python 的 (?<!\d)(\d{6})(?!\d)）
    assert_eq!(otp::extract_otp("order 1234567 shipped"), None);
    assert_eq!(otp::extract_otp("id 12345"), None);
    assert_eq!(otp::extract_otp("no digits here"), None);
    assert_eq!(otp::extract_all("a 111111 b 222222 c"), vec!["111111", "222222"]);
}

const SAMPLE_INBOX_HTML: &str = r#"
<html><body>
  <article>
    <div class="meta">时间：2026-10-27 02:33:10</div>
    <div class="code">778324</div>
  </article>
  <article>
    <div class="meta">时间：2026-10-27 02:30:00</div>
    <div class="code">111111</div>
  </article>
</body></html>
"#;

#[test]
fn otp_extracts_from_inbox_cards() {
    let cards = otp::parse_cards(SAMPLE_INBOX_HTML);
    assert_eq!(cards.len(), 2, "应解析出 2 张卡片: {cards:?}");
    assert_eq!(cards[0].otp(), Some("778324".to_string()));
    assert_eq!(cards[1].otp(), Some("111111".to_string()));
    assert!(cards[0].meta[0].contains("2026-10-27"));
}

#[test]
fn otp_card_timestamp_parsing() {
    // 2026-10-27 02:33:10 UTC
    assert_eq!(
        otp::parse_meta_timestamp("时间：2026-10-27 02:33:10"),
        Some(1_793_068_390)
    );
    assert_eq!(otp::parse_meta_timestamp("Time: 2026/10/27 02:33"), Some(1_793_068_380));
    assert_eq!(otp::parse_meta_timestamp("no timestamp"), None);
}

#[test]
fn otp_selects_newest_fresh_card() {
    // after_ts 早于最新卡片 → 取最新那张
    let code = otp::select_fresh_otp(SAMPLE_INBOX_HTML, Some(1_793_068_000), &HashSet::new());
    assert_eq!(code, Some("778324".to_string()));

    // after_ts 晚于全部卡片 → 都不新鲜
    let code = otp::select_fresh_otp(SAMPLE_INBOX_HTML, Some(1_793_069_999), &HashSet::new());
    assert_eq!(code, None);
}

#[test]
fn otp_undated_cards_must_differ_from_baseline() {
    let html = r#"
    <article><div class="code">222222</div></article>
    <article><div class="code">333333</div></article>
    "#;
    let baseline: HashSet<String> = ["222222".to_string()].into_iter().collect();
    assert_eq!(
        otp::select_fresh_otp(html, Some(1_793_068_000), &baseline),
        Some("333333".to_string())
    );
}

// ─────────────────────────── TOTP（RFC 6238 向量）───────────────────────────

const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

#[test]
fn totp_rfc6238_sha1_vectors() {
    // RFC 6238 附录 B（SHA1，8 位）
    let cases: &[(u64, &str)] = &[
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ];
    for (t, expected) in cases {
        assert_eq!(
            twofa::totp_at(RFC_SECRET_B32, *t, 8, 30).unwrap(),
            *expected,
            "T={t} 的 TOTP 不符"
        );
    }
}

#[test]
fn hotp_six_digits_and_secret_normalization() {
    // 6 位 = 8 位向量的后 6 位
    assert_eq!(twofa::hotp(RFC_SECRET_B32, 1, 6).unwrap(), "287082");
    // base32 容忍小写/空格/无 padding
    assert_eq!(
        twofa::hotp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 1, 6).unwrap(),
        "287082"
    );
    assert_eq!(
        twofa::decode_secret(RFC_SECRET_B32).unwrap(),
        b"12345678901234567890".to_vec()
    );
    assert!(twofa::hotp("not-base32!!", 1, 6).is_err());
}

#[test]
fn totp_verify_allows_one_step_window() {
    let code_at_1111111109 = twofa::totp_at(RFC_SECRET_B32, 1_111_111_109, 6, 30).unwrap();
    // 30 秒后（下一个窗口）仍然接受
    assert!(twofa::verify_totp_at(RFC_SECRET_B32, &code_at_1111111109, 1_111_111_111).unwrap());
    // 明显过期（3 个窗口之后）不接受
    assert!(!twofa::verify_totp_at(RFC_SECRET_B32, &code_at_1111111109, 1_111_111_191).unwrap());
    // 错误码不接受
    assert!(!twofa::verify_totp_at(RFC_SECRET_B32, "000000", 1_111_111_109).unwrap());
}

// ─────────────────────────── SQLite ───────────────────────────

#[test]
fn store_creates_schema_and_roundtrips_account() {
    let store = Store::open_in_memory().unwrap();
    store.init().unwrap();
    // 幂等
    store.init().unwrap();
    assert_eq!(store.schema_version().unwrap(), store::SCHEMA_VERSION);
    assert_eq!(store.count().unwrap(), 0);

    let mut account = Account::new("user@example.invalid", "P@ssw0rd-123456");
    account.access_token = "at-123".to_string();
    account.totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
    account.cookies = "oai-did=abc; __Secure-next-auth.session-token=def".to_string();
    account.status = "registered".to_string();
    let id = store.save_account(&account).unwrap();
    assert!(id > 0);

    let loaded = store.get_account("user@example.invalid").unwrap().unwrap();
    assert_eq!(loaded.email, account.email);
    assert_eq!(loaded.password, account.password);
    assert_eq!(loaded.access_token, "at-123");
    assert_eq!(loaded.totp_secret, account.totp_secret);
    assert!(loaded.cookies.contains("oai-did=abc"));
    assert_eq!(loaded.status, "registered");
    assert_eq!(store.count().unwrap(), 1);
}

#[test]
fn store_upsert_keeps_single_row() {
    let store = Store::open_in_memory().unwrap();
    store.init().unwrap();

    let mut account = Account::new("dup@example.invalid", "first-password");
    let id1 = store.save_account(&account).unwrap();

    account.password = "second-password".to_string();
    account.status = "registered".to_string();
    let id2 = store.save_account(&account).unwrap();

    assert_eq!(id1, id2, "upsert 不应新增行");
    assert_eq!(store.count().unwrap(), 1);
    let loaded = store.get_account("dup@example.invalid").unwrap().unwrap();
    assert_eq!(loaded.password, "second-password");
    assert_eq!(loaded.status, "registered");
    assert_eq!(store.list_accounts(10).unwrap().len(), 1);
}

// ─────────────────────────── 配置解析 ───────────────────────────

#[test]
fn config_defaults_are_dry_run() {
    let cfg = RegisterConfig::from_lookup(lookup_from(&[])).unwrap();
    assert_eq!(cfg.count, 1);
    assert!(cfg.dry_run, "默认必须 dry-run");
    assert!(cfg.email_api.is_none());
    assert!(cfg.proxy.is_none());
    assert!(!cfg.enable_2fa);
    assert_eq!(cfg.db_path.to_string_lossy(), "data/sentinel-rs.db");
    assert_eq!(cfg.otp_max_wait_secs, 180);
    assert_eq!(cfg.otp_poll_interval_secs, 3);
    cfg.require_live_prerequisites().unwrap(); // dry-run 不要求邮箱 API
}

#[test]
fn config_parses_values_and_clamps_interval() {
    let cfg = RegisterConfig::from_lookup(lookup_from(&[
        ("SENTINEL_COUNT", " 3 "),
        ("SENTINEL_ENABLE_2FA", "true"),
        ("OTP_MAX_WAIT", "60"),
        ("OTP_POLL_INTERVAL", "0"),
        ("SENTINEL_PROXY", "127.0.0.1:7890"),
        ("REG_MAIL_API_BASE_URL", "https://mail.example.invalid/"),
        ("REG_MAIL_API_TOKEN", "token-abc"),
        ("SENTINEL_LIVE_REGISTER", "1"),
    ]))
    .unwrap();

    assert_eq!(cfg.count, 3);
    assert!(cfg.enable_2fa);
    assert_eq!(cfg.otp_max_wait_secs, 60);
    assert_eq!(cfg.otp_poll_interval_secs, 1, "轮询间隔 0 会被夹到 1");
    assert_eq!(cfg.proxy.as_deref(), Some("127.0.0.1:7890"));
    assert!(!cfg.dry_run);
    let api = cfg.email_api.as_ref().expect("邮箱 API 应已解析");
    assert_eq!(api.base_url, "https://mail.example.invalid");
    assert_eq!(api.token, "token-abc");
    cfg.require_live_prerequisites().unwrap();
}

#[test]
fn config_rejects_bad_values_with_clear_errors() {
    let err = RegisterConfig::from_lookup(lookup_from(&[("SENTINEL_COUNT", "abc")])).unwrap_err();
    assert!(format!("{err:#}").contains("SENTINEL_COUNT"), "错误信息应点名变量: {err:#}");

    let err = RegisterConfig::from_lookup(lookup_from(&[("SENTINEL_COUNT", "0")])).unwrap_err();
    assert!(format!("{err:#}").contains("必须 >= 1"));

    let err = RegisterConfig::from_lookup(lookup_from(&[("REG_MAIL_API_BASE_URL", "http://x.invalid")]))
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("https://") && msg.contains("REG_MAIL_ALLOW_INSECURE"), "{msg}");

    let err = RegisterConfig::from_lookup(lookup_from(&[("SENTINEL_PROXY", "::bad::proxy::")]))
        .unwrap_err();
    assert!(format!("{err:#}").contains("代理"), "{err:#}");
}

#[test]
fn config_live_mode_requires_email_api() {
    let cfg = RegisterConfig::from_lookup(lookup_from(&[("SENTINEL_LIVE_REGISTER", "1")])).unwrap();
    let err = cfg.require_live_prerequisites().unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("REG_MAIL_API_BASE_URL"), "{msg}");
}

#[test]
fn config_rejects_token_without_base_url() {
    let err = RegisterConfig::from_lookup(lookup_from(&[("REG_MAIL_API_TOKEN", "t")])).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("REG_MAIL_API_TOKEN") && msg.contains("REG_MAIL_API_BASE_URL"), "{msg}");
}

// ─────────────────────────── 邮箱 API 客户端 ───────────────────────────

#[test]
fn email_config_from_env_values() {
    assert!(EmailApiConfig::from_lookup(&lookup_from(&[])).unwrap().is_none());

    let cfg = EmailApiConfig::from_lookup(&lookup_from(&[
        ("REG_MAIL_API_BASE_URL", "https://mail.example.invalid///"),
        ("REG_MAIL_API_TOKEN", " tok "),
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(cfg.base_url, "https://mail.example.invalid");
    assert_eq!(cfg.token, "tok");
    assert!(!cfg.allow_insecure);
    assert_eq!(
        cfg.endpoint("mailboxes"),
        "https://mail.example.invalid/mailboxes"
    );

    // token 可选：只给 base_url 也能用，请求不带 Authorization
    let anon = EmailApiConfig::from_lookup(&lookup_from(&[(
        "REG_MAIL_API_BASE_URL",
        "https://m.example.invalid/",
    )]))
    .unwrap()
    .unwrap();
    assert_eq!(anon.token, "");
    let client = email::MailApiClient::new_offline(anon);
    let spec = client.create_mailbox_spec(None, None);
    assert_eq!(spec.method, Method::Post);
    assert_eq!(spec.url, "https://m.example.invalid/mailboxes");
    assert!(spec.header("authorization").is_none(), "token 为空不该发鉴权头");
}

#[test]
fn email_allows_insecure_only_for_loopback_with_opt_in() {
    // http:// + 未开逃生门 → 拒绝，并点名叫用户设 REG_MAIL_ALLOW_INSECURE
    let err = EmailApiConfig::from_lookup(&lookup_from(&[(
        "REG_MAIL_API_BASE_URL",
        "http://127.0.0.1:8899/api/v1",
    )]))
    .unwrap_err();
    assert!(format!("{err:#}").contains("REG_MAIL_ALLOW_INSECURE"), "{err:#}");

    // http:// + 逃生门 + 回环 → 放行
    let cfg = EmailApiConfig::from_lookup(&lookup_from(&[
        ("REG_MAIL_API_BASE_URL", "http://127.0.0.1:8899/api/v1"),
        ("REG_MAIL_ALLOW_INSECURE", "1"),
    ]))
    .unwrap()
    .unwrap();
    assert!(cfg.allow_insecure);
    assert_eq!(
        cfg.endpoint("mailboxes"),
        "http://127.0.0.1:8899/api/v1/mailboxes"
    );

    // http:// + 逃生门 + 非回环 → 仍然拒绝
    let err = EmailApiConfig::from_lookup(&lookup_from(&[
        ("REG_MAIL_API_BASE_URL", "http://mail.example.invalid"),
        ("REG_MAIL_ALLOW_INSECURE", "1"),
    ]))
    .unwrap_err();
    assert!(format!("{err:#}").contains("回环"), "{err:#}");

    assert!(email::is_loopback_url("http://127.0.0.1:8899/x"));
    assert!(email::is_loopback_url("http://localhost:8899/x"));
    assert!(email::is_loopback_url("http://[::1]:8899/x"));
    assert!(!email::is_loopback_url("http://mail.example.invalid/x"));
}

#[test]
fn email_parses_mailbox_and_error_responses() {
    let mailbox = email::parse_mailbox_response(
        201,
        r#"{"email":"a@example.invalid","code_url":"https://mail.example.invalid/c/abc","expires_at":"2026-10-27T03:00:00Z"}"#,
        false,
    )
    .unwrap();
    assert_eq!(mailbox.email, "a@example.invalid");
    assert!(mailbox.code_url.starts_with("https://"));
    assert_eq!(mailbox.expires_at.as_deref(), Some("2026-10-27T03:00:00Z"));

    let err = email::parse_mailbox_response(401, r#"{"error":"unauthorized"}"#, false).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("HTTP 401") && msg.contains("unauthorized"), "{msg}");

    // 非 https 的取码页地址默认拒绝
    let err = email::parse_mailbox_response(
        201,
        r#"{"email":"a@example.invalid","code_url":"http://insecure/c/abc"}"#,
        false,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("https"), "{err:#}");

    // 逃生门下的回环 http 取码页可以解析（本地 mock）
    let local = email::parse_mailbox_response(
        201,
        r#"{"email":"a@example.invalid","code_url":"http://127.0.0.1:8899/inbox/abc"}"#,
        true,
    )
    .unwrap();
    assert_eq!(local.code_url, "http://127.0.0.1:8899/inbox/abc");

    assert!(email::parse_health_response(200, r#"{"ok":true}"#).is_ok());
    assert!(email::parse_health_response(200, r#"{"ok":false}"#).is_err());
}

// ─────────────────────────── 请求构造 / 响应解析 ───────────────────────────

#[test]
fn auth_builder_produces_expected_requests() {
    let builder = AuthRequestBuilder::new("UA/1.0", "en-US,en;q=0.9", "device-1234");
    let st = SentinelToken {
        token: "sentinel-token".to_string(),
        so_token: Some("so-token".to_string()),
    };

    let spec = builder.authorize_continue("a@example.invalid", "sentinel-token", "signup");
    assert_eq!(spec.method, Method::Post);
    assert_eq!(spec.url, auth::EP_AUTHORIZE_CONTINUE);
    assert_eq!(spec.header(auth::HDR_SENTINEL), Some("sentinel-token"));
    let body = spec.body.as_ref().unwrap();
    assert_eq!(body["username"]["value"], "a@example.invalid");
    assert_eq!(body["username"]["kind"], "email");
    assert_eq!(body["screen_hint"], "signup");
    assert_eq!(spec.header(auth::HDR_DEVICE_ID), Some("device-1234"));
    assert!(spec.header(auth::HDR_INVOCATION_ID).is_some());
    assert_eq!(spec.header(auth::HDR_NAVIGATION_ID), Some(builder.navigation_id().as_str()));

    let spec = builder.register_password("a@example.invalid", "P@ss-1234", &st);
    assert_eq!(spec.url, auth::EP_USER_REGISTER);
    assert_eq!(spec.header(auth::HDR_SENTINEL_SO), Some("so-token"));
    let body = spec.body.unwrap();
    assert_eq!(body["username"], "a@example.invalid");
    assert_eq!(body["password"], "P@ss-1234");

    let spec = builder.send_otp(&st);
    assert_eq!(spec.method, Method::Get);
    assert_eq!(spec.url, auth::EP_OTP_SEND);
    assert!(spec.body.is_none());

    let spec = builder.verify_otp("778324", &st);
    assert_eq!(spec.url, auth::EP_OTP_VALIDATE);
    assert_eq!(spec.body.unwrap()["code"], "778324");

    let spec = builder.create_account_with("James Smith", "1990-05-17", &st);
    assert_eq!(spec.url, auth::EP_CREATE_ACCOUNT);
    let body = spec.body.unwrap();
    assert_eq!(body["name"], "James Smith");
    assert_eq!(body["birthdate"], "1990-05-17");

    // 每次调用都铸新的 invocation id，但同文档内 navigation id 不变
    let a = builder.verify_otp("111111", &st);
    let b = builder.create_account(&st);
    assert_ne!(
        a.header(auth::HDR_INVOCATION_ID),
        b.header(auth::HDR_INVOCATION_ID)
    );
    assert_eq!(
        a.header(auth::HDR_NAVIGATION_ID),
        b.header(auth::HDR_NAVIGATION_ID)
    );
    // 整页导航后换成新值
    let old = builder.navigation_id();
    let new = builder.new_document_navigation();
    assert_ne!(old, new);
    assert_eq!(builder.navigation_id(), new);
}

#[test]
fn auth_parses_responses_and_errors() {
    let parsed = auth::parse_authorize_continue(
        r#"{"page":{"type":"email_otp_verification"},"continue_url":"https://auth.openai.com/email-verification"}"#,
    )
    .unwrap();
    assert_eq!(parsed.page.as_ref().unwrap().kind, "email_otp_verification");
    assert!(parsed.continue_url.contains("/email-verification"));

    let empty = auth::parse_authorize_continue("").unwrap();
    assert!(empty.page.is_none() && empty.continue_url.is_empty());

    assert!(auth::parse_create_account("not json").is_err());
    let created = auth::parse_create_account(r#"{"continue_url":"https://chatgpt.com/"}"#).unwrap();
    assert_eq!(created.continue_url, "https://chatgpt.com/");

    let msg = auth::describe_api_error(
        409,
        r#"{"error":{"message":"invalid_state","code":"invalid_state"}}"#,
    );
    assert!(msg.contains("409") && msg.contains("invalid_state"), "{msg}");
}

#[test]
fn auth_classifies_landing_urls() {
    assert_eq!(
        auth::classify_landing("https://auth.openai.com/create-account/password", Intent::Signup),
        Landing::New
    );
    assert_eq!(
        auth::classify_landing("https://auth.openai.com/email-verification", Intent::Signup),
        Landing::New
    );
    assert_eq!(
        auth::classify_landing("https://auth.openai.com/email-verification", Intent::Login),
        Landing::Existing
    );
    assert_eq!(
        auth::classify_landing("https://auth.openai.com/log-in/password", Intent::Signup),
        Landing::Existing
    );
    assert_eq!(auth::classify_landing("", Intent::Signup), Landing::Unknown);
    assert_eq!(
        auth::classify_landing("https://auth.openai.com/whatever", Intent::Signup),
        Landing::Unknown
    );
}

#[test]
fn auth_random_identity_looks_sane() {
    let password = auth::random_password(16);
    assert_eq!(password.chars().count(), 16);
    assert!(password.chars().any(|c| c.is_ascii_lowercase()));
    assert!(password.chars().any(|c| c.is_ascii_uppercase()));
    assert!(password.chars().any(|c| c.is_ascii_digit()));
    assert!(password.chars().any(|c| !c.is_ascii_alphanumeric()));

    let name = auth::random_name();
    assert_eq!(name.split(' ').count(), 2, "姓名应为两段: {name}");

    let birthdate = auth::random_birthdate();
    let year: u32 = birthdate[..4].parse().unwrap();
    assert!((1985..=2000).contains(&year), "生日年份越界: {birthdate}");
}

#[test]
fn http_retry_policy_and_proxy_normalization() {
    let policy = RetryPolicy::default();
    assert_eq!(policy.max_attempts, 3);
    assert!(policy.should_retry(1, None), "传输错误应重试");
    assert!(policy.should_retry(1, Some(500)));
    assert!(policy.should_retry(1, Some(429)));
    assert!(!policy.should_retry(1, Some(404)));
    assert!(!policy.should_retry(3, Some(500)), "达到上限后不再重试");
    assert_eq!(policy.delay_ms(1), 400);
    assert_eq!(policy.delay_ms(2), 800);
    assert_eq!(policy.delay_ms(3), 1600);

    let no_429 = RetryPolicy {
        retry_on_429: false,
        ..RetryPolicy::default()
    };
    assert!(!no_429.should_retry(1, Some(429)));

    assert_eq!(
        http::normalize_proxy_url("127.0.0.1:7890").unwrap(),
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        http::normalize_proxy_url("socks5://user:pass@10.0.0.1:1080").unwrap(),
        "socks5://user:pass@10.0.0.1:1080"
    );
    assert!(http::normalize_proxy_url("   ").is_err());
}

#[test]
fn http_request_spec_headers_and_redaction() {
    let mut spec = RequestSpec::get("demo", "https://example.invalid/x")
        .with_headers(vec![("accept".to_string(), "application/json".to_string())]);
    spec.set_header("Accept", "text/plain");
    assert_eq!(spec.header("accept"), Some("text/plain"));
    assert_eq!(spec.headers.len(), 1, "同名 header 应覆盖而不是追加");

    let mut spec = RequestSpec::post_json(
        "demo.post",
        "https://example.invalid/y",
        Some(vec![("openai-sentinel-token".to_string(), "0123456789abcdef".to_string())]),
        Some(serde_json::json!({"code": "123456"})),
    );
    let described = spec.describe_with_headers();
    assert!(described.contains("POST https://example.invalid/y"));
    assert!(!described.contains("0123456789abcdef"), "敏感头应脱敏: {described}");
    assert!(described.contains("123456"));

    spec.set_header("x-extra", "v");
    assert_eq!(spec.header("X-Extra"), Some("v"));
}

// ─────────────────────────── 2FA 请求构造 ───────────────────────────

#[test]
fn twofa_builds_enroll_and_activate_requests() {
    let builder = AuthRequestBuilder::new("UA/1.0", "en-US", "device-xyz");
    let st = SentinelToken::default();

    let info = twofa::mfa_info_spec(&builder, "at-1", &st);
    assert_eq!(info.method, Method::Get);
    assert_eq!(info.url, "https://chatgpt.com/backend-api/accounts/mfa_info");
    assert_eq!(info.header("authorization"), Some("Bearer at-1"));

    let enroll = twofa::enroll_spec(&builder, "at-1", &st);
    assert_eq!(enroll.url, "https://chatgpt.com/backend-api/accounts/mfa/enroll");
    assert_eq!(enroll.body.unwrap()["factor_type"], "totp");

    let activate = twofa::activate_spec(&builder, "at-1", "123456", "sess-9", &st);
    assert_eq!(
        activate.url,
        "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
    );
    let body = activate.body.unwrap();
    assert_eq!(body["code"], "123456");
    assert_eq!(body["session_id"], "sess-9");
    assert_eq!(body["factor_type"], "totp");
}

#[test]
fn twofa_parses_enroll_and_mfa_info() {
    let parsed = twofa::parse_enroll(
        r#"{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","session_id":"s-1","factor":{"id":"f-1"}}"#,
    )
    .unwrap();
    assert_eq!(parsed.session_id, "s-1");
    assert_eq!(parsed.factor_id(), "f-1");

    assert!(twofa::parse_enroll(r#"{"secret":"","session_id":"s"}"#).is_err());
    assert!(twofa::parse_enroll("nope").is_err());

    let info = twofa::parse_mfa_info(r#"{"mfa_enabled":true,"factors":{"totp":{"id":"f-1"}}}"#)
        .unwrap();
    assert!(twofa::already_enrolled(&info));
    let info = twofa::parse_mfa_info(r#"{"mfa_enabled":false}"#).unwrap();
    assert!(!twofa::already_enrolled(&info));
}

// ─────────────────────────── 编排（dry-run，不联网）───────────────────────────

#[test]
fn dry_run_plan_is_offline_and_complete() {
    let cfg = RegisterConfig::default();
    assert!(cfg.dry_run);
    let identity = RegisterIdentity::placeholder();
    let plan = flow::build_plan(&cfg, &identity);
    let labels: Vec<&str> = plan.iter().map(|spec| spec.label).collect();

    assert_eq!(labels[0], "email.health");
    for expected in [
        "auth.authorize_continue",
        "auth.navigation",
        "auth.user_register",
        "auth.email_otp_send",
        "auth.email_otp_validate",
        "auth.create_account",
    ] {
        assert!(labels.contains(&expected), "计划缺 {expected}: {labels:?}");
    }
    assert!(!labels.contains(&"2fa.enroll"), "未开 2FA 时不该有 enroll");

    let cfg_2fa = RegisterConfig {
        enable_2fa: true,
        ..RegisterConfig::default()
    };
    let plan_2fa = flow::build_plan(&cfg_2fa, &identity);
    let labels_2fa: Vec<&str> = plan_2fa.iter().map(|spec| spec.label).collect();
    assert!(labels_2fa.contains(&"2fa.mfa_info"));
    assert!(labels_2fa.contains(&"2fa.enroll"));
    assert!(labels_2fa.contains(&"2fa.activate"));

    // 计划里不应出现真实 token：sentinel 头在日志里被脱敏
    let described = plan
        .iter()
        .map(|spec| spec.describe_with_headers())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(described.contains("dryrun+"));
    assert!(described.contains("<redacted>"), "sentinel 头应被脱敏: {described}");
    assert!(
        !described.contains("由 mint 生成>"),
        "占位 token 不应原样出现在日志里: {described}"
    );
}

#[test]
fn register_once_in_dry_run_does_not_touch_network() {
    let cfg = RegisterConfig::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = runtime.block_on(flow::register_once(&cfg)).unwrap();
    assert!(outcome.dry_run);
    assert!(!outcome.plan.is_empty());
    assert!(outcome.email.starts_with("dryrun+"));
    assert!(outcome.email.ends_with("@example.invalid"));
    assert_eq!(outcome.access_token, None);
    assert_eq!(outcome.account_id, None);
}

#[test]
fn missing_sentinel_source_reports_todo() {
    let err = flow::MissingSentinelSource
        .token("authorize_continue", "device-1")
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("TODO(mint)"), "{msg}");
    assert!(msg.contains("authorize_continue"), "{msg}");
}
