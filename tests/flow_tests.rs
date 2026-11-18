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
fn email_allows_insecure_only_with_opt_in() {
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

    // http:// + 逃生门 + **非回环**（自建 http://IP:PORT）→ 也放行
    let remote = EmailApiConfig::from_lookup(&lookup_from(&[
        ("REG_MAIL_API_BASE_URL", "http://198.51.100.7:28012/api/plus/v4"),
        ("REG_MAIL_ALLOW_INSECURE", "1"),
    ]))
    .unwrap()
    .unwrap();
    assert!(remote.allow_insecure);
    assert_eq!(
        remote.endpoint("getcode"),
        "http://198.51.100.7:28012/api/plus/v4/getcode"
    );

    // 非回环 http:// 未开逃生门 → 仍然拒绝（默认安全，点名开关）
    let err = EmailApiConfig::from_lookup(&lookup_from(&[(
        "REG_MAIL_API_BASE_URL",
        "http://198.51.100.7:28012/api/plus/v4",
    )]))
    .unwrap_err();
    assert!(format!("{err:#}").contains("REG_MAIL_ALLOW_INSECURE"), "{err:#}");

    // 逃生门开关的解析（大小写 / 多种真值）
    for raw in ["1", "true", "YES", "on"] {
        assert!(
            email::allow_insecure_from_lookup(&lookup_from(&[(
                "REG_MAIL_ALLOW_INSECURE",
                raw
            )])),
            "{raw} 应视为开启"
        );
    }
    for raw in ["0", "false", "off", "no", ""] {
        assert!(
            !email::allow_insecure_from_lookup(&lookup_from(&[(
                "REG_MAIL_ALLOW_INSECURE",
                raw
            )])),
            "{raw} 应视为关闭"
        );
    }

    assert!(email::is_loopback_url("http://127.0.0.1:8899/x"));
    assert!(email::is_loopback_url("http://localhost:8899/x"));
    assert!(email::is_loopback_url("http://[::1]:8899/x"));
    assert!(!email::is_loopback_url("http://mail.example.invalid/x"));
    assert_eq!(
        email::url_host("http://203.0.113.7:8080/api/x?id=a@b").as_deref(),
        Some("203.0.113.7")
    );
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

// ─────────────────────── 静态邮箱池 / 代理清单 ───────────────────────

/// 建一个独立的临时目录（每个测试一套，避免互相踩）。
fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sentinel-rs-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn static_email_pool_parses_lines() {
    let ok = email::parse_static_email_line(
        "user@example.invalid----https://mail.example.invalid/share/v1/code?link=abc&token=def",
    )
    .unwrap()
    .expect("应解析出一行");
    assert_eq!(ok.email, "user@example.invalid");
    assert_eq!(
        ok.code_url,
        "https://mail.example.invalid/share/v1/code?link=abc&token=def"
    );
    assert_eq!(ok.expires_at, None);

    // 空行 / 注释行跳过
    assert!(email::parse_static_email_line("   ").unwrap().is_none());
    assert!(email::parse_static_email_line("# comment").unwrap().is_none());

    // 格式不对要报错（而不是静默当一个空邮箱）
    assert!(email::parse_static_email_line("no-separator").is_err());
    assert!(email::parse_static_email_line("bad@x----https://ok.invalid").is_ok());
    assert!(email::parse_static_email_line("noat----https://ok.invalid").is_err());
    assert!(email::parse_static_email_line("a@b----ftp://nope").is_err());
}

#[test]
fn static_email_pool_accepts_http_only_with_opt_in() {
    let line = "a@example.invalid----http://198.51.100.7:28012/api/plus/v4/getcode?id=a@example.invalid";

    // 默认拒绝明文 http，并点名叫用户开 REG_MAIL_ALLOW_INSECURE
    let err = email::parse_static_email_line(line).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REG_MAIL_ALLOW_INSECURE") && msg.contains("https://"),
        "{msg}"
    );

    // 开关打开 → 放行任意 host（含 http://IP:PORT）
    let ok = email::parse_static_email_line_with(line, true)
        .unwrap()
        .expect("应解析出一行");
    assert_eq!(ok.email, "a@example.invalid");
    assert_eq!(
        ok.code_url,
        "http://198.51.100.7:28012/api/plus/v4/getcode?id=a@example.invalid"
    );

    // https 在两种开关下都放行
    assert!(email::parse_static_email_line_with(
        "a@example.invalid----https://mail.example.invalid/c",
        false
    )
    .is_ok());
    assert!(email::parse_static_email_line_with(
        "a@example.invalid----https://mail.example.invalid/c",
        true
    )
    .is_ok());
}

#[test]
fn static_email_pool_skips_bad_lines_with_line_numbers() {
    let dir = temp_dir("email-pool-skip");
    let pool_path = dir.join("mails.txt");
    let text = "# header\n\
                a1@example.invalid----https://mail.example.invalid/c?link=1\n\
                \n\
                broken-line-without-separator\n\
                noat----https://mail.example.invalid/c?link=2\n\
                a2@example.invalid----ftp://nope\n\
                a3@example.invalid----http://198.51.100.7:28012/api/getcode?id=a3@example.invalid\n\
                a4@example.invalid----https://mail.example.invalid/c?link=4\n";
    std::fs::write(&pool_path, text).unwrap();

    // 默认（明文 http 拒绝）：只有 2 条 https 合法，4 行被跳过
    let pool = email::StaticEmailPool::new(&pool_path);
    assert!(!pool.allow_insecure());
    let scan = pool.scan().unwrap();
    assert_eq!(scan.file_lines, 8);
    assert_eq!(scan.skipped_count(), 4);
    assert_eq!(
        scan.entries.iter().map(|m| m.email.as_str()).collect::<Vec<_>>(),
        vec!["a1@example.invalid", "a4@example.invalid"]
    );
    // 跳过的行号 + 原因都要在（不能静默）
    let skipped_lines: Vec<usize> = scan.skipped.iter().map(|(n, _)| *n).collect();
    assert_eq!(skipped_lines, vec![4, 5, 6, 7]);
    assert!(scan.skipped.iter().all(|(_, reason)| !reason.is_empty()));

    // 开开关：http 那一行也变成合法（3 条），其余 3 行仍然报错跳过
    let insecure = email::StaticEmailPool::new_with_insecure(&pool_path, true);
    let scan2 = insecure.scan().unwrap();
    assert_eq!(scan2.entries.len(), 3);
    assert_eq!(scan2.skipped_count(), 3);
    assert_eq!(
        scan2.skipped.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        vec![4, 5, 6]
    );

    // `next()` 遇到坏行是"告警 + 跳过"，不是整批失败
    let first = pool.next().unwrap();
    assert_eq!(first.email, "a1@example.invalid");
    let second = pool.next().unwrap();
    assert_eq!(second.email, "a4@example.invalid", "坏行应被跳过而不是中止");

    // 只解析不取用：scan 不写 .used、不建锁文件
    assert!(!pool.lock_path().exists());
    let scan3 = pool.scan().unwrap();
    assert_eq!(scan3.used_entries, 2, "两条已取用的应被标记");
}

#[test]
fn static_email_pool_strips_utf8_bom() {
    let dir = temp_dir("email-pool-bom");
    let path = dir.join("mails.txt");
    std::fs::write(
        &path,
        "\u{feff}u1@example.invalid----https://m.example.invalid/c?x=1\n\
         u2@example.invalid----https://m.example.invalid/c?x=2\n",
    )
    .unwrap();
    let scan = email::StaticEmailPool::new(&path).scan().unwrap();
    assert_eq!(scan.skipped_count(), 0);
    assert_eq!(
        scan.entries.iter().map(|m| m.email.as_str()).collect::<Vec<_>>(),
        vec!["u1@example.invalid", "u2@example.invalid"],
        "第一行的 UTF-8 BOM 必须被剥掉"
    );
}

#[test]
fn static_email_pool_used_file_is_per_path() {
    let dir = temp_dir("email-pool-perpath");
    let a = dir.join("a.txt");
    let b = dir.join("b.txt");
    std::fs::write(&a, "u1@example.invalid----https://m.example.invalid/c?x=1\n").unwrap();
    std::fs::write(&b, "u1@example.invalid----https://m.example.invalid/c?x=1\n").unwrap();

    let pa = email::StaticEmailPool::new(&a);
    let pb = email::StaticEmailPool::new(&b);
    assert_ne!(pa.used_path(), pb.used_path(), "不同清单的 .used 必须分开");

    assert_eq!(pa.next().unwrap().email, "u1@example.invalid");
    // 同一邮箱在另一个清单里仍然可用（互不污染）
    assert_eq!(pb.next().unwrap().email, "u1@example.invalid");
    // 各自用尽
    assert!(pa.next().is_err());
    assert!(pb.next().is_err());
    assert!(std::fs::read_to_string(pa.used_path()).unwrap().contains("u1@example.invalid"));
    assert!(std::fs::read_to_string(pb.used_path()).unwrap().contains("u1@example.invalid"));
}

#[test]
fn static_email_pool_uses_each_line_once_and_tracks_used_file() {
    let dir = temp_dir("email-pool");
    let pool_path = dir.join("mails.txt");
    std::fs::write(
        &pool_path,
        "# header\n\
         a1@example.invalid----https://mail.example.invalid/c?link=1&token=a\n\
         \n\
         a2@example.invalid----https://mail.example.invalid/c?link=2&token=b\n\
         a3@example.invalid----https://mail.example.invalid/c?link=3&token=c\n",
    )
    .unwrap();

    let pool = email::StaticEmailPool::new(&pool_path);
    assert_eq!(pool.used_path(), dir.join("mails.txt.used"));
    assert_eq!(pool.lock_path(), dir.join("mails.txt.lock"));

    let first = pool.next().unwrap();
    assert_eq!(first.email, "a1@example.invalid");
    let second = pool.next().unwrap();
    assert_eq!(second.email, "a2@example.invalid");

    // used 文件按行追加
    let used = std::fs::read_to_string(pool.used_path()).unwrap();
    assert_eq!(
        used.lines().collect::<Vec<_>>(),
        vec!["a1@example.invalid", "a2@example.invalid"]
    );

    // 锁文件用完即删
    assert!(!pool.lock_path().exists(), "锁文件应已释放");

    // 新实例（模拟重跑）跳过已用过的两行
    let pool2 = email::StaticEmailPool::new(&pool_path);
    let third = pool2.next().unwrap();
    assert_eq!(third.email, "a3@example.invalid");

    // 用尽后报错，而不是复用
    let err = pool2.next().unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("静态邮箱池已用尽"), "{msg}");
}

#[test]
fn static_email_pool_never_hands_out_the_same_line_twice() {
    let dir = temp_dir("email-concurrent");
    let pool_path = dir.join("mails.txt");
    let mut text = String::new();
    for i in 0..8 {
        text.push_str(&format!(
            "u{i}@example.invalid----https://mail.example.invalid/c?link={i}\n"
        ));
    }
    std::fs::write(&pool_path, text).unwrap();

    // 8 个线程同时抢：每行只能被取一次
    let mut handles = Vec::new();
    for _ in 0..8 {
        let path = pool_path.clone();
        handles.push(std::thread::spawn(move || {
            email::StaticEmailPool::new(path).next().map(|m| m.email)
        }));
    }
    let mut got: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().unwrap().expect("并发下每线程都应拿到一个邮箱"))
        .collect();
    got.sort();
    got.dedup();
    assert_eq!(got.len(), 8, "8 个线程必须拿到 8 个不同邮箱: {got:?}");
}

#[test]
fn proxy_pool_parses_host_port_user_pass_and_rotates() {
    // 代理清单风格：host:port:user:pass
    let url = http::ProxyPool::parse_line("proxy.example.com:8080:user-abc:pass-word")
        .unwrap()
        .expect("应解析出一行");
    assert_eq!(url, "http://user-abc:pass-word@proxy.example.com:8080");

    // 无鉴权 / 带 scheme / 注释 / 非法端口
    assert_eq!(
        http::ProxyPool::parse_line("10.0.0.1:8080").unwrap().unwrap(),
        "http://10.0.0.1:8080"
    );
    assert_eq!(
        http::ProxyPool::parse_line("socks5h://127.0.0.1:10808")
            .unwrap()
            .unwrap(),
        "socks5h://127.0.0.1:10808"
    );
    assert!(http::ProxyPool::parse_line("").unwrap().is_none());
    assert!(http::ProxyPool::parse_line("# x").unwrap().is_none());
    assert!(http::ProxyPool::parse_line("host:notaport").is_err());
    assert!(http::ProxyPool::parse_line("hostonly").is_err());

    // userinfo 里的特殊字符要 percent-encode，否则 URL 会解析歪
    let encoded = http::ProxyPool::parse_line("h:1:u@x:p@ss").unwrap().unwrap();
    assert_eq!(encoded, "http://u%40x:p%40ss@h:1");

    // 文件 + 轮换：第 N 个账号用第 N % len 条
    let dir = temp_dir("proxy-pool");
    let path = dir.join("proxies.txt");
    std::fs::write(
        &path,
        "h1:1111:u1:p1\n\
         h2:2222:u2:p2\n\
         h3:3333:u3:p3\n",
    )
    .unwrap();
    let pool = http::ProxyPool::load(&path).unwrap();
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.pick(0).unwrap(), "http://u1:p1@h1:1111");
    assert_eq!(pool.pick(1).unwrap(), "http://u2:p2@h2:2222");
    assert_eq!(pool.pick(2).unwrap(), "http://u3:p3@h3:3333");
    assert_eq!(pool.pick(3).unwrap(), "http://u1:p1@h1:1111", "取模轮换");
    assert_eq!(pool.pick(4).unwrap(), "http://u2:p2@h2:2222");
}

#[test]
fn register_config_prefers_static_mail_pool_and_proxy_rotation() {
    let dir = temp_dir("config-pool");
    let mail = dir.join("mails.txt");
    std::fs::write(
        &mail,
        "s1@example.invalid----https://mail.example.invalid/c?link=1\n",
    )
    .unwrap();
    let proxies = dir.join("proxies.txt");
    std::fs::write(&proxies, "h1:1111:u1:p1\nh2:2222:u2:p2\n").unwrap();

    let cfg = RegisterConfig::from_lookup(lookup_from(&[
        ("REG_MAIL_EMAIL_FILE", mail.to_str().unwrap()),
        ("SENTINEL_PROXY_FILE", proxies.to_str().unwrap()),
        ("SENTINEL_LIVE_REGISTER", "1"),
    ]))
    .unwrap();

    // 静态池优先，且不要求 REG_MAIL_API_BASE_URL
    assert!(cfg.static_email_pool.is_some());
    assert!(cfg.email_api.is_none());
    assert!(cfg.mailbox_source().contains("静态池"));
    cfg.require_live_prerequisites().unwrap();

    // 代理按账号轮换；`--proxy` 仍然优先
    assert_eq!(
        cfg.proxy_for_account(0).as_deref(),
        Some("http://u1:p1@h1:1111")
    );
    assert_eq!(
        cfg.proxy_for_account(1).as_deref(),
        Some("http://u2:p2@h2:2222")
    );
    assert_eq!(
        cfg.proxy_for_account(2).as_deref(),
        Some("http://u1:p1@h1:1111")
    );
    let mut with_proxy = cfg.clone();
    with_proxy.proxy = Some("socks5h://127.0.0.1:10808".to_string());
    assert_eq!(
        with_proxy.proxy_for_account(1).as_deref(),
        Some("socks5h://127.0.0.1:10808"),
        "单代理必须优先于清单"
    );

    // 静态池与 API 同时设置时静态池优先（互斥语义）
    let both = RegisterConfig::from_lookup(lookup_from(&[
        ("REG_MAIL_EMAIL_FILE", mail.to_str().unwrap()),
        ("REG_MAIL_API_BASE_URL", "https://mail.example.invalid"),
        ("SENTINEL_LIVE_REGISTER", "1"),
    ]))
    .unwrap();
    assert!(both.static_email_pool.is_some());
    assert!(both.mailbox_source().contains("静态池"));
}

#[test]
fn otp_reads_json_code_pages() {
    use std::collections::HashSet;

    let body = r#"{"code":"746194","cursor":149362,"kind":"code+link","link":"https://chatgpt.com","mail_time":"2026-11-17 15:25:50","ok":true,"received_at":1794929150,"recipient":"a@example.invalid","sender":"chatgpt <x@example.invalid>","status":"received","subject":"Your temporary ChatGPT verification code"}"#;

    let empty = HashSet::new();
    // 新鲜（received_at 不早于请求开始 - 5s）
    assert_eq!(
        otp::select_code_from_json(body, Some(1_794_929_100), &empty).as_deref(),
        Some("746194")
    );
    // 太旧（早于请求开始 5s 以上）→ 不是本次的码
    assert_eq!(
        otp::select_code_from_json(body, Some(1_794_930_000), &empty),
        None
    );
    // baseline 里已有 → 不算新
    let baseline: HashSet<String> = ["746194".to_string()].into_iter().collect();
    assert_eq!(otp::select_code_from_json(body, None, &baseline), None);

    // 嵌套 / 数字形态 / 毫秒时间戳也能读
    let nested = r#"{"ok":true,"data":{"otp":746195,"received_at":1794929150000}}"#;
    assert_eq!(
        otp::select_code_from_json(nested, Some(1_794_929_100), &empty).as_deref(),
        Some("746195")
    );

    // HTML 页面不会被误当成 JSON
    assert_eq!(
        otp::select_code_from_json("<html>123456</html>", None, &empty),
        None
    );
    // 非法 JSON 不 panic
    assert_eq!(otp::select_code_from_json("{\"code\":", None, &empty), None);
}

#[test]
fn otp_treats_pending_json_as_no_code() {
    use std::collections::HashSet;

    let empty = HashSet::new();
    // 实测形态：还没有验证码
    let pending = r#"{"code":"no_code","message":"暂未收到验证码","retryable":true,"success":false}"#;
    assert_eq!(
        otp::select_code_from_json(pending, None, &empty),
        None,
        "no_code 不能被当成验证码"
    );
    assert_eq!(
        otp::select_code_from_json(pending, Some(1_794_929_100), &empty),
        None
    );
    let reason = otp::json_pending_reason(pending).expect("应识别为待机响应");
    assert!(reason.contains("success=false"), "{reason}");

    // success=false 时即使带了 6 位数字也不取（避免把上一轮的码当新码）
    assert_eq!(
        otp::select_code_from_json(r#"{"success":false,"code":"123456"}"#, None, &empty),
        None
    );
    // 空 / null / 无 code 字段
    for body in [
        r#"{"code":null}"#,
        r#"{"code":""}"#,
        r#"{"message":"暂未收到验证码","retryable":true}"#,
        r#"{"ok":false,"retryable":true}"#,
    ] {
        assert_eq!(otp::select_code_from_json(body, None, &empty), None, "{body}");
        assert!(otp::json_pending_reason(body).is_some(), "{body}");
    }

    // 正常 6 位码 → 直接返回（且不算待机）
    let body = r#"{"code":"123456","message":"已收到","success":true}"#;
    assert_eq!(
        otp::select_code_from_json(body, None, &empty).as_deref(),
        Some("123456")
    );
    assert!(otp::json_pending_reason(body).is_none());

    // 嵌套：data.code / result.code / 数字形态
    assert_eq!(
        otp::select_code_from_json(
            r#"{"success":true,"data":{"code":"654321"}}"#,
            None,
            &empty
        )
        .as_deref(),
        Some("654321")
    );
    assert_eq!(
        otp::select_code_from_json(r#"{"result":{"code":"112233"}}"#, None, &empty).as_deref(),
        Some("112233")
    );
    assert_eq!(
        otp::select_code_from_json(r#"{"data":{"code":998877}}"#, None, &empty).as_deref(),
        Some("998877")
    );
    // 嵌套里的 no_code 也不算码
    assert_eq!(
        otp::select_code_from_json(r#"{"data":{"code":"no_code"},"success":true}"#, None, &empty),
        None
    );
    // 非 JSON 不误判
    assert!(otp::json_pending_reason("<html>暂未收到验证码</html>").is_none());
    assert!(!otp::looks_like_json("<html></html>"));
    assert!(otp::looks_like_json(r#" {"code":"1"} "#));
}

// ─────────────────── 出口国家探测（Python _probe_country_before_fingerprint）───────────────────
#[test]
fn trace_country_is_parsed_from_loc_line() {
    let trace = "fl=1f2abc\nh=cloudflare.com\nip=203.0.113.9\nts=1794929150.123\nvisit_scheme=https\nuag=curl\ncolo=SIN\nsliver=none\nhttp=http/2\nloc=IN\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n";
    assert_eq!(flow::parse_trace_country(trace).as_deref(), Some("IN"));

    // 大小写归一 + 行内前后空白
    assert_eq!(flow::parse_trace_country("loc=jp\n").as_deref(), Some("JP"));
    assert_eq!(
        flow::parse_trace_country("  loc=de  \n").as_deref(),
        Some("DE")
    );

    // 取第一行 loc=（Python 也是遇到就 return）
    assert_eq!(
        flow::parse_trace_country("loc=US\nloc=JP\n").as_deref(),
        Some("US")
    );

    // 非法 / 缺失
    assert_eq!(flow::parse_trace_country(""), None);
    assert_eq!(flow::parse_trace_country("no loc line here"), None);
    assert_eq!(flow::parse_trace_country("loc=\n"), None);
    assert_eq!(flow::parse_trace_country("loc=INDIA\n"), None);
    assert_eq!(flow::parse_trace_country("ip=1.2.3.4\n"), None);
    // Tor 的 loc=T1：Python 会原样返回，这里返回后由 country_profile 按未知国家兜底
    assert_eq!(flow::parse_trace_country("loc=T1\n").as_deref(), Some("T1"));
}

#[test]
fn geo_probe_switch_reads_env_like_python() {
    // 默认开启
    assert!(flow::geo_probe_enabled_from_lookup(&lookup_from(&[])));
    // 各种关闭写法
    for raw in ["0", "false", "FALSE", "off", "no"] {
        assert!(
            !flow::geo_probe_enabled_from_lookup(&lookup_from(&[("SENTINEL_FP_GEO_PROBE", raw)])),
            "{raw} 应关闭探测"
        );
    }
    // 其它值仍然开启
    for raw in ["1", "true", "yes", "on", "anything"] {
        assert!(
            flow::geo_probe_enabled_from_lookup(&lookup_from(&[("SENTINEL_FP_GEO_PROBE", raw)])),
            "{raw} 应保持开启"
        );
    }
}

#[test]
fn geo_probe_disabled_sends_no_request() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    // 指向一个必然连不上的地址：只要发了请求，耗时会明显上升
    let got = runtime.block_on(flow::probe_exit_country_if(
        false,
        Some("socks5h://127.0.0.1:1"),
    ));
    assert_eq!(got, None);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "关闭开关后不应发起任何网络请求（耗时 {:?}）",
        started.elapsed()
    );
}

#[test]
fn geo_probe_failure_falls_back_to_default_profile() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // 关闭端口 → 探测失败返回 None，不 panic
    let country = runtime.block_on(flow::probe_exit_country_if(
        true,
        Some("http://127.0.0.1:1"),
    ));
    assert_eq!(country, None, "探测失败必须优雅返回 None");

    // 退回默认画像（UTC + en-US），与 Python `_DEFAULT_COUNTRY_PROFILE` 一致
    let fp = sentinel_rs::fingerprint::DeviceFingerprint::generate_for_country(
        Some("geo-fallback"),
        country.as_deref(),
    );
    assert_eq!(fp.timezone, "UTC");
    assert_eq!(fp.lang, "en-US");
    assert_eq!(fp.platform, "Win32");
    assert!(
        fp.user_agent
            .contains(&format!("Chrome/{}", fp.browser_version)),
        "UA 必须与 browser_version 同档: {}",
        fp.user_agent
    );
    assert!(fp.version_consistency().is_ok(), "{:?}", fp.version_consistency());
}

#[test]
fn fingerprint_follows_probed_country() {
    // 探测到 IN → 指纹落在印度画像（Asia/Kolkata / en-IN）
    let country = flow::parse_trace_country("loc=IN\n").expect("loc=IN");
    let fp = sentinel_rs::fingerprint::DeviceFingerprint::generate_for_country(
        Some("geo-seed"),
        Some(&country),
    );
    assert_eq!(fp.country_code, "IN");
    assert_eq!(fp.timezone, "Asia/Kolkata");
    assert_eq!(fp.lang, "en-IN");
    assert_eq!(fp.locale, "en-IN");
    assert!(fp.lang_full.starts_with("en-IN"));
    assert!(
        fp.user_agent
            .contains(&format!("Chrome/{}", fp.browser_version)),
        "UA 必须与 browser_version 同档: {}",
        fp.user_agent
    );
    assert_eq!(fp.platform, "Win32");

    // 配置层面：fp_country 优先于环境里的空值
    let mut cfg = RegisterConfig::default();
    cfg.fp_country = Some("IN".to_string());
    let resolved = cfg.resolve_fingerprint().expect("应生成指纹");
    assert_eq!(resolved.timezone, "Asia/Kolkata");

    // 显式国家优先于探测：SENTINEL_FP_COUNTRY 在 from_lookup 阶段就定死
    let cfg = RegisterConfig::from_lookup(lookup_from(&[
        ("SENTINEL_FP_COUNTRY", "jp"),
        ("SENTINEL_FP_GEO_PROBE", "0"),
    ]))
    .unwrap();
    assert_eq!(cfg.fp_country.as_deref(), Some("JP"));
    let fp = cfg.resolve_fingerprint().expect("应生成指纹");
    assert_eq!(fp.timezone, "Asia/Tokyo");
    assert_eq!(fp.lang, "ja-JP");
}

// ─────────────────── 资源路径：运行期解析（不再编译期固化）───────────────────

#[test]
fn repo_asset_resolution_works_without_compile_time_path() {
    use sentinel_rs::paths;

    // 显式指定仓库根目录时必须能找到（这也是打包/搬家后的逃生门）
    let root = paths::repo_root_candidates()
        .into_iter()
        .find(|p| p.join("sample_challenge.json").is_file())
        .expect("测试环境里应能从某个候选根目录找到 sample_challenge.json");
    std::env::set_var(paths::REPO_ROOT_ENV, &root);
    let found = paths::find_repo_file("sample_challenge.json").expect("应找到 challenge");
    assert!(found.is_file(), "{}", found.display());
    let expected = paths::find_repo_file("tests/token_expected.json").expect("应找到 expected");
    assert!(expected.is_file(), "{}", expected.display());
    std::env::remove_var(paths::REPO_ROOT_ENV);

    // 找不到时错误里要列出尝试过的路径（而不是 panic）
    let err = paths::find_repo_file("definitely-not-here-xyz.json").unwrap_err();
    assert!(err.contains("definitely-not-here-xyz.json"), "{err}");
    assert!(err.contains("尝试过"), "{err}");
    assert!(err.contains(paths::REPO_ROOT_ENV), "{err}");
}
