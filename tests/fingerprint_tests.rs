//! 设备指纹生成器的离线单测（不联网、不读真实配置）。
//!
//! 覆盖三条硬约束：
//! 1. **可复现**：同 seed 两次生成完全一致，不同 seed 至少一项不同；
//! 2. **自洽**：UA 版本 ↔ emulation 档位 ↔ `sec-ch-ua` 品牌版本三方一致；
//! 3. **区域**：时区与主语言必须来自 [`REGIONS`] 的同一行，不交叉组合。

use sentinel_rs::fingerprint::{self, DeviceFingerprint, BROWSER_VERSIONS, REGIONS};
use sentinel_rs::flow::RegisterConfig;

/// 一批固定 seed：足够覆盖到每个离散分支，又完全确定性。
fn seeds() -> Vec<String> {
    (0..96).map(|i| format!("fp-seed-{i}")).collect()
}

/// 主语言：`ja-JP,ja;q=0.9,en;q=0.8` → `ja-JP`。
fn primary_language(accept_language: &str) -> String {
    accept_language
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 时区在 [`REGIONS`] 里的那一行：`(country, timezone, language)`。
fn region_of(timezone: &str) -> Option<(&'static str, &'static str, &'static str)> {
    REGIONS
        .iter()
        .copied()
        .find(|(_, tz, _)| *tz == timezone)
}

fn assert_base62(text: &str) {
    assert!(
        text.chars()
            .all(|c| c.is_ascii_alphanumeric()),
        "fingerprint_id 必须是 base62: {text}"
    );
}

// ─────────────────────────── 1. 可复现 ───────────────────────────

#[test]
fn same_seed_generates_identical_fingerprint() {
    for seed in seeds() {
        let a = DeviceFingerprint::generate(Some(&seed));
        let b = DeviceFingerprint::generate(Some(&seed));
        // 整体相等就覆盖了 UA / CH / 屏幕 / 时区 / 语言 / 硬件 / dpr / id
        assert_eq!(a, b, "同 seed 两次生成的指纹必须完全一致（seed={seed}）");
        assert_eq!(a.fingerprint_id, b.fingerprint_id, "seed={seed}");
    }
}

#[test]
fn different_seeds_generate_different_fingerprints() {
    let mut seen: Vec<DeviceFingerprint> = Vec::new();
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(
            !seen.contains(&fp),
            "不同 seed 生成了完全相同的指纹（seed={seed}）"
        );
        seen.push(fp);
    }

    // 相邻 seed 至少有一项不同（不能"随便换 seed 结果不变"）
    let a = DeviceFingerprint::generate(Some("alpha"));
    let b = DeviceFingerprint::generate(Some("beta"));
    assert_ne!(a, b);
}

// ─────────────────────────── 2. 版本 / 平台自洽 ───────────────────────────

#[test]
fn browser_version_matches_emulation_and_client_hints() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        let major = fp
            .browser_version
            .split('.')
            .next()
            .expect("版本号第一段");

        assert!(
            BROWSER_VERSIONS
                .iter()
                .any(|(version, _)| *version == fp.browser_version),
            "版本必须来自白名单: {}",
            fp.browser_version
        );
        assert_eq!(
            fp.emulation,
            format!("Chrome{major}"),
            "emulation 档位必须与 UA 版本同档（seed={seed}）"
        );
        assert!(
            fp.user_agent.contains(&format!("Chrome/{}", fp.browser_version)),
            "UA 里的版本号与 browser_version 不一致: {}",
            fp.user_agent
        );
        assert!(
            fp.sec_ch_ua
                .contains(&format!("\"Chromium\";v=\"{major}\"")),
            "sec-ch-ua 的 Chromium 版本必须是 {major}: {}",
            fp.sec_ch_ua
        );
        assert!(
            fp.sec_ch_ua
                .contains(&format!("\"Google Chrome\";v=\"{major}\"")),
            "sec-ch-ua 的 Google Chrome 版本必须是 {major}: {}",
            fp.sec_ch_ua
        );
        assert_eq!(fp.sec_ch_ua_mobile, "?0", "桌面端 sec-ch-ua-mobile 恒为 ?0");
    }
}

#[test]
fn platform_fields_are_coherent() {
    let mut macs = 0;
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        match fp.platform.as_str() {
            "Win32" => {
                assert!(fp.user_agent.contains("Windows NT 10.0; Win64; x64"), "{}", fp.user_agent);
                assert_eq!(fp.sec_ch_ua_platform, "\"Windows\"");
            }
            "MacIntel" => {
                macs += 1;
                assert!(
                    fp.user_agent.contains("Macintosh; Intel Mac OS X 10_15_7"),
                    "{}",
                    fp.user_agent
                );
                assert_eq!(fp.sec_ch_ua_platform, "\"macOS\"");
            }
            other => panic!("未知平台: {other}"),
        }
        assert_eq!(fp.vendor, "Google Inc.");
    }
    assert!(macs > 0, "96 个 seed 里应该至少抽到一次 macOS");
    assert!(macs < 96, "96 个 seed 里应该至少抽到一次 Windows");
}

// ─────────────────────────── 3. 时区 ↔ 语言 ───────────────────────────

#[test]
fn timezone_and_language_come_from_same_region_row() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        let (country, timezone, language) = region_of(&fp.timezone)
            .unwrap_or_else(|| panic!("时区 {} 不在 REGIONS 表里（seed={seed}）", fp.timezone));
        assert_eq!(fp.timezone, timezone);
        assert_eq!(
            primary_language(&fp.accept_language),
            language,
            "时区 {country}/{timezone} 的主语言必须是 {language}（seed={seed}）"
        );
        assert_eq!(fp.languages, fp.accept_language);
        assert!(
            fp.accept_language.starts_with(language),
            "accept_language 必须以主语言开头: {}",
            fp.accept_language
        );
        assert!(
            fp.accept_language.split(',').count() >= 2,
            "accept_language 至少要有主语言 + 基语言: {}",
            fp.accept_language
        );
    }
}

#[test]
fn regions_cover_the_required_timezones() {
    for (country, timezone, language) in [
        ("JP", "Asia/Tokyo", "ja-JP"),
        ("CN", "Asia/Shanghai", "zh-CN"),
        ("US", "America/New_York", "en-US"),
        ("GB", "Europe/London", "en-GB"),
        ("DE", "Europe/Berlin", "de-DE"),
        ("SG", "Asia/Singapore", "en-SG"),
        ("AU", "Australia/Sydney", "en-AU"),
    ] {
        assert!(
            REGIONS.contains(&(country, timezone, language)),
            "REGIONS 缺 {country}/{timezone}/{language}"
        );
    }

    // 时区必须能被 token 的时区表解析，否则 profile 里的 offset 会退成默认 +540
    for (_, timezone, _) in REGIONS {
        assert!(
            sentinel_rs::token::tz_table(timezone).is_some(),
            "REGIONS 里的时区 {timezone} 不在 token::tz_table 中"
        );
    }
}

#[test]
fn country_forces_the_region() {
    let fp = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("JP"));
    assert_eq!(fp.timezone, "Asia/Tokyo");
    assert_eq!(primary_language(&fp.accept_language), "ja-JP");

    // 大小写不敏感
    let lower = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("jp"));
    assert_eq!(lower, fp, "国家代码大小写不应影响结果");

    // 未知国家 → 回退到全量随机（不能 panic，也不能生成非法值）
    let unknown = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("ZZ"));
    assert!(region_of(&unknown.timezone).is_some());

    // 同 seed 但不同国家：时区跟着国家走
    let gb = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("GB"));
    assert_eq!(gb.timezone, "Europe/London");
    assert_eq!(primary_language(&gb.accept_language), "en-GB");
}

// ─────────────────────────── 4. 屏幕 / 硬件 / id ───────────────────────────

#[test]
fn screen_and_hardware_within_documented_ranges() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(fp.screen_height >= 700, "screen_height 必须 >= 700: {}x{}", fp.screen_width, fp.screen_height);
        assert!(fp.screen_width > fp.screen_height, "桌面屏幕应是横向: {}x{}", fp.screen_width, fp.screen_height);
        assert!(
            [1.0, 1.25, 1.5, 2.0].contains(&fp.device_pixel_ratio),
            "dpr 只允许 {{1.0, 1.25, 1.5, 2.0}}，实际 {}",
            fp.device_pixel_ratio
        );
        assert!(
            [4, 8, 12, 16].contains(&fp.hardware_concurrency),
            "hardware_concurrency 越界: {}",
            fp.hardware_concurrency
        );
        assert!(
            [4, 8, 16].contains(&fp.device_memory),
            "device_memory 越界: {}",
            fp.device_memory
        );
    }
}

#[test]
fn fingerprint_id_is_prefixed_base62() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(fp.fingerprint_id.starts_with(fingerprint::FINGERPRINT_ID_PREFIX));
        let body = fp
            .fingerprint_id
            .strip_prefix(fingerprint::FINGERPRINT_ID_PREFIX)
            .expect("前缀");
        assert_eq!(body.chars().count(), 16, "id 主体必须是 16 位: {}", fp.fingerprint_id);
        assert_base62(body);
    }
}

// ─────────────────────────── 5. profile / 配置接线 ───────────────────────────

#[test]
fn profile_options_mirror_the_fingerprint() {
    for seed in ["p-1", "p-2", "p-3"].iter() {
        let fp = DeviceFingerprint::generate(Some(seed));
        let options = fp.profile_options();

        assert_eq!(options.user_agent.as_deref(), Some(fp.user_agent.as_str()));
        assert_eq!(options.screen.as_deref(), Some(fp.screen().as_str()));
        assert_eq!(options.screen.as_deref(), Some(format!("{}x{}", fp.screen_width, fp.screen_height).as_str()));
        assert_eq!(options.lang.as_deref(), Some(fp.primary_language().as_str()));
        assert_eq!(options.languages.as_deref(), Some(fp.languages.as_str()));
        assert_eq!(options.platform.as_deref(), Some(fp.platform.as_str()));
        assert_eq!(options.vendor.as_deref(), Some(fp.vendor.as_str()));
        assert_eq!(options.hardware_concurrency, Some(fp.hardware_concurrency));
        assert_eq!(options.device_memory, Some(fp.device_memory));
        assert_eq!(options.device_pixel_ratio, Some(fp.device_pixel_ratio));
        assert_eq!(options.timezone.as_deref(), Some(fp.timezone.as_str()));
    }
}

#[test]
fn explicit_user_agent_disables_random_fingerprint() {
    let cfg = RegisterConfig::default();
    assert!(cfg.fingerprint.is_none());
    assert!(!cfg.has_ua_override(), "默认配置不算显式覆盖");

    // 不随机时：resolve 直接给出一套指纹，并投影到 UA / 语言
    let resolved = cfg.resolve_fingerprint().expect("默认应生成指纹");
    let applied = cfg.clone().with_fingerprint();
    let applied_fp = applied.fingerprint.as_ref().expect("配置里应写入指纹");
    assert_eq!(applied.user_agent, applied_fp.user_agent);
    assert_eq!(applied.accept_language, applied_fp.languages);

    // 显式覆盖 UA / 语言 → 不随机，原值保持不变
    let mut fixed = RegisterConfig::default();
    fixed.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                        Chrome/120.0.0.0 Safari/537.36"
        .to_string();
    fixed.accept_language = "de-DE,de;q=0.9".to_string();
    assert!(fixed.has_ua_override());
    assert!(fixed.resolve_fingerprint().is_none());
    let fixed_applied = fixed.clone().with_fingerprint();
    assert!(fixed_applied.fingerprint.is_none());
    assert_eq!(fixed_applied.user_agent, fixed.user_agent);
    assert_eq!(fixed_applied.accept_language, "de-DE,de;q=0.9");

    // 注入的指纹优先于现生成
    let mut injected = RegisterConfig::default();
    injected.fingerprint = Some(DeviceFingerprint::generate(Some("injected-seed")));
    assert_eq!(injected.resolve_fingerprint(), injected.fingerprint);
    assert_eq!(resolved.timezone, region_of(&resolved.timezone).expect("区域").1);
}

#[test]
fn auth_builder_headers_follow_the_fingerprint() {
    use sentinel_rs::flow::auth::AuthRequestBuilder;

    for seed in ["h-1", "h-2", "h-3"] {
        let fp = DeviceFingerprint::generate(Some(seed));
        let builder = AuthRequestBuilder::new("placeholder-ua", "en-US", "did-1")
            .with_fingerprint(&fp);

        assert_eq!(builder.user_agent(), fp.user_agent);
        assert_eq!(builder.accept_language(), fp.languages);

        let hints = builder
            .client_hints()
            .expect("指纹路径必须发 client hints（不再因为平台不是 Windows 就不发）");
        assert_eq!(hints.sec_ch_ua, fp.sec_ch_ua);
        assert_eq!(hints.sec_ch_ua_mobile, fp.sec_ch_ua_mobile);
        assert_eq!(hints.sec_ch_ua_platform, fp.sec_ch_ua_platform);

        // 真实请求头里的值也必须是同一份
        let spec = builder.chat_session();
        assert_eq!(spec.header("sec-ch-ua"), Some(fp.sec_ch_ua.as_str()));
        assert_eq!(
            spec.header("sec-ch-ua-platform"),
            Some(fp.sec_ch_ua_platform.as_str())
        );
        assert_eq!(spec.header("accept-language"), Some(fp.languages.as_str()));
    }
}

#[test]
fn token_profile_matches_the_fingerprint() {
    for seed in ["t-1", "t-2", "t-3"] {
        let fp = DeviceFingerprint::generate(Some(seed));
        let profile = sentinel_rs::flow::sentinel::profile_from_fp(&fp);

        assert_eq!(profile.user_agent, fp.user_agent);
        assert_eq!(profile.platform, fp.platform);
        assert_eq!(profile.vendor, fp.vendor);
        assert_eq!(profile.language, fp.primary_language());
        assert_eq!(profile.languages[0], fp.primary_language());
        assert_eq!(profile.timezone_name, fp.timezone);
        assert_eq!(profile.screen_width, fp.screen_width);
        assert_eq!(profile.screen_height, fp.screen_height);
        assert_eq!(profile.hardware_concurrency, fp.hardware_concurrency);
        assert_eq!(profile.device_memory, fp.device_memory);
        assert_eq!(profile.device_pixel_ratio, fp.device_pixel_ratio);

        // 时区偏移必须和时区名对得上（不能一边说 Europe/London 一边用 +540）
        let expected = sentinel_rs::token::tz_table(&fp.timezone)
            .expect("区域表里的时区必须在 tz_table 中")
            .offset;
        assert_eq!(profile.timezone_offset, expected, "时区 {} 的偏移不对", fp.timezone);
        assert_ne!(profile.tz_label, fp.timezone, "时区标签不该退化成 IANA 名");
    }
}

#[test]
fn summary_contains_version_platform_timezone_screen_and_id() {
    let fp = DeviceFingerprint::generate(Some("summary-seed"));
    let summary = fp.summary();
    assert!(summary.contains(&fp.browser_version), "{summary}");
    assert!(summary.contains(&fp.platform), "{summary}");
    assert!(summary.contains(&fp.timezone), "{summary}");
    assert!(summary.contains(&fp.screen()), "{summary}");
    assert!(summary.contains(&format!("fp={}", fp.fingerprint_id)), "{summary}");
}
