//! 设备指纹生成器的离线单测（不联网、不读真实配置）。
//!
//! 对齐 Python 协议机（真机对齐版）`协议/fingerprint.py` 的硬约束，并在此之上扩池：
//! 1. **Chrome 只在 Windows**：`platform == "Win32"`、UA 含 `Windows NT 10.0`、
//!    `sec-ch-ua-platform == "Windows"`、`vendor == "Google Inc."`；
//! 2. **版本三兄弟分开、但同属一个档位**：UA `Chrome/<major>.0.0.0`、
//!    `sec-ch-ua` 的 `v="<major>"`、`full-version-list` 用同档真实构建号，
//!    且 **UA major == `sec-ch-ua` major == TLS 档版本**（硬规则，四档各测一次）；
//! 3. **可复现**：同 seed 两次生成完全一致；
//! 4. **自洽**：`viewport == screen`、`locale == lang`、`lang_full` 以 `lang` 开头；
//! 5. **加权重池**：屏幕 11 档 × dpr 5 档 × 核数 9 档 × 内存 3 档 × TLS 4 档
//!    = 5940 种设备组合（[`DEVICE_COMBINATIONS`]），抽样 500 次至少出现 400 种。

use sentinel_rs::fingerprint::{
    self, DeviceFingerprint, CHROME_UA_ARCH, CHROME_UA_BITNESS, CHROME_UA_MODEL, CHROME_VERSIONS,
    COUNTRY_PROFILES, DEFAULT_COUNTRY_PROFILE, DEVICE_COMBINATIONS, DEVICE_MEMORY,
    DEVICE_PIXEL_RATIOS, HARDWARE_CONCURRENCY, MAX_CHROME_MAJOR, NAVIGATOR_PLATFORM,
    NAVIGATOR_VENDOR, WIN_SCREENS,
};
use sentinel_rs::flow::RegisterConfig;

/// 从 UA 里取 `Chrome/<major>` 的 major。
fn ua_major_of(user_agent: &str) -> String {
    let rest = user_agent
        .split("Chrome/")
        .nth(1)
        .unwrap_or_else(|| panic!("UA 里没有 Chrome/<ver>: {user_agent}"));
    rest.split(['.', ' ']).next().unwrap_or("").to_string()
}

/// 从 `sec-ch-ua` 里取 `"Google Chrome";v="<major>"` 的 major。
fn sec_ch_major_of(sec_ch_ua: &str) -> String {
    let rest = sec_ch_ua
        .split("\"Google Chrome\";v=\"")
        .nth(1)
        .unwrap_or_else(|| panic!("sec-ch-ua 里没有 Google Chrome: {sec_ch_ua}"));
    rest.split('"')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("")
        .to_string()
}

/// TLS 档位名 → major（`Chrome149` → `149`）。
fn tls_major_of(emulation: &str) -> String {
    emulation
        .strip_prefix("Chrome")
        .unwrap_or_else(|| panic!("emulation 不是 Chrome<ver> 形态: {emulation}"))
        .to_string()
}

/// 一批固定 seed：足够覆盖到每个离散分支，又完全确定性。
fn seeds() -> Vec<String> {
    (0..96).map(|i| format!("fp-seed-{i}")).collect()
}

/// 验收用的 20 套：与真实注册同一入口（`generate`，不指定国家）。
fn acceptance_batch() -> Vec<DeviceFingerprint> {
    (0..20)
        .map(|i| DeviceFingerprint::generate(Some(&format!("accept-{i}"))))
        .collect()
}

/// `ja-JP,zh-CN;q=0.9,en;q=0.8` → `["ja-JP", "zh-CN", "en"]`。
fn lang_list_of(accept_language: &str) -> Vec<String> {
    fingerprint::split_accept_language(accept_language)
}

/// 时区归属的国家画像；`UTC` 归兜底画像（Python `_DEFAULT_COUNTRY_PROFILE`）。
fn profile_of_timezone(timezone: &str) -> Option<&'static fingerprint::CountryProfile> {
    COUNTRY_PROFILES
        .iter()
        .find(|p| p.timezones.iter().any(|&(tz, _)| tz == timezone))
        .or_else(|| {
            DEFAULT_COUNTRY_PROFILE
                .timezones
                .iter()
                .any(|&(tz, _)| tz == timezone)
                .then_some(&DEFAULT_COUNTRY_PROFILE)
        })
}

/// 屏幕是否在白名单里（带权重）。
fn screen_in_pool(width: i64, height: i64) -> bool {
    WIN_SCREENS
        .iter()
        .any(|&(w, h, _)| w == width && h == height)
}

/// dpr 是否在白名单里。
fn dpr_in_pool(dpr: f64) -> bool {
    DEVICE_PIXEL_RATIOS.iter().any(|&(v, _)| v == dpr)
}

/// 核数是否在白名单里。
fn cores_in_pool(cores: i64) -> bool {
    HARDWARE_CONCURRENCY.iter().any(|&(v, _)| v == cores)
}

/// 内存是否在白名单里。
fn memory_in_pool(memory: i64) -> bool {
    DEVICE_MEMORY.iter().any(|&(v, _)| v == memory)
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

    let a = DeviceFingerprint::generate(Some("alpha"));
    let b = DeviceFingerprint::generate(Some("beta"));
    assert_ne!(a, b);
}

// ─────────────────────────── 2. 验收断言（20 套）───────────────────────────

#[test]
fn acceptance_batch_matches_python_truth() {
    let batch = acceptance_batch();
    assert_eq!(batch.len(), 20);

    for (i, fp) in batch.iter().enumerate() {
        // ① 平台：Chrome 只能是 Windows
        assert_eq!(fp.platform, NAVIGATOR_PLATFORM, "[{i}] platform 必须是 Win32");
        assert_eq!(fp.platform, "Win32", "[{i}] platform");
        assert!(
            fp.user_agent.contains("(Windows NT 10.0; Win64; x64)"),
            "[{i}] UA 必须是 Windows: {}",
            fp.user_agent
        );
        assert!(
            !fp.user_agent.contains("Macintosh") && !fp.user_agent.contains("Mac OS X"),
            "[{i}] 不允许出现 macOS UA: {}",
            fp.user_agent
        );
        assert_eq!(fp.sec_ch_ua_platform, "\"Windows\"", "[{i}] sec-ch-ua-platform");
        assert_eq!(fp.sec_ch_ua_mobile, "?0", "[{i}] sec-ch-ua-mobile");
        assert_eq!(fp.vendor, NAVIGATOR_VENDOR, "[{i}] vendor 必须是 Google Inc.");

        // ② 版本三兄弟同档：UA `Chrome/<major>.0.0.0`，major == TLS 档 == sec-ch-ua
        let tier = CHROME_VERSIONS
            .iter()
            .find(|c| c.impersonate == fp.impersonate)
            .unwrap_or_else(|| panic!("[{i}] impersonate 必须来自版本表: {}", fp.impersonate));
        assert_eq!(fp.browser_version, tier.ua_ver, "[{i}] browser_version");
        assert_eq!(fp.chrome_major, tier.ver, "[{i}] chrome_major");
        assert!(
            fp.user_agent
                .contains(&format!("Chrome/{}", tier.ua_ver)),
            "[{i}] UA 必须含 Chrome/{}: {}",
            tier.ua_ver,
            fp.user_agent
        );
        assert_eq!(fp.ua_major().as_deref(), Some(tier.ver), "[{i}] UA major");
        assert_eq!(fp.tls_major(), Some(tier.ver), "[{i}] TLS 档版本");
        assert_eq!(fp.sec_ch_ua_major(), Some(tier.ver), "[{i}] sec-ch-ua major");
        assert!(
            fp.version_consistency().is_ok(),
            "[{i}] 版本必须自洽: {:?}",
            fp.version_consistency()
        );
        assert!(
            tier.ver.parse::<u32>().unwrap() <= MAX_CHROME_MAJOR.parse::<u32>().unwrap(),
            "[{i}] 声称的版本不能超过 wreq-util 最高档 {}",
            MAX_CHROME_MAJOR
        );

        // ③ sec-ch-ua：同档 major，且三段顺序/名字逐字对齐真机
        assert_eq!(
            fp.sec_ch_ua,
            format!(
                "\"Chromium\";v=\"{v}\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"{v}\"",
                v = tier.ver
            ),
            "[{i}] sec-ch-ua 必须由同一档派生"
        );

        // ④ device_memory ≤ 8（spec 封顶）
        assert!(
            (2..=8).contains(&fp.device_memory),
            "[{i}] device_memory 必须 ≤ 8: {}",
            fp.device_memory
        );
        assert!(memory_in_pool(fp.device_memory), "[{i}] device_memory 越界");
        assert!(cores_in_pool(fp.hardware_concurrency), "[{i}] 核数越界");

        // ⑤ viewport == screen
        assert_eq!(
            (fp.viewport_w, fp.viewport_h),
            (fp.screen_width, fp.screen_height),
            "[{i}] viewport 必须与 screen 完全相同"
        );
        assert_eq!(fp.viewport(), fp.screen(), "[{i}] viewport() == screen()");

        // ⑥ locale == lang
        assert_eq!(fp.locale, fp.lang, "[{i}] locale 必须等于 lang");
        assert_eq!(fp.primary_language(), fp.lang, "[{i}] primary_language");

        // ⑦ lang_full 以 lang 开头
        assert!(
            fp.lang_full.starts_with(&fp.lang),
            "[{i}] lang_full 必须以 lang 开头: {} / {}",
            fp.lang,
            fp.lang_full
        );
        assert!(
            !fp.lang_full.is_empty() && fp.accept_language == fp.lang_full,
            "[{i}] accept-language 与 lang_full 同源"
        );
        assert_eq!(
            lang_list_of(&fp.lang_full).first().map(String::as_str),
            Some(fp.lang.as_str()),
            "[{i}] languages[0] 必须是 lang"
        );

        // ⑧ 其它真机约束
        assert_eq!(fp.max_touch_points, 0, "[{i}] 桌面 Chrome 触摸点为 0");
        assert!(!fp.is_mobile, "[{i}] 桌面 Chrome 不是 mobile");
        assert!(!fp.has_touch, "[{i}] has_touch 与 max_touch_points 一致");
        assert!(
            dpr_in_pool(fp.device_pixel_ratio),
            "[{i}] dpr 越界: {}",
            fp.device_pixel_ratio
        );
        assert!(
            screen_in_pool(fp.screen_width, fp.screen_height),
            "[{i}] 屏幕必须在白名单里: {}",
            fp.screen()
        );
        assert_eq!(fp.ua_arch, CHROME_UA_ARCH, "[{i}] ua_arch");
        assert_eq!(fp.ua_bitness, CHROME_UA_BITNESS, "[{i}] ua_bitness");
        assert_eq!(fp.ua_model, CHROME_UA_MODEL, "[{i}] ua_model 必须是 \"\" 形态");
        assert_eq!(fp.ua_platform_version, "15.0.0", "[{i}] platform_version");
        assert!(
            fp.ua_full_version_list.contains(&format!("\"{}\"", tier.full_ver)),
            "[{i}] full-version-list 必须是同档真实构建号 {}: {}",
            tier.full_ver,
            fp.ua_full_version_list
        );
        assert_eq!(fp.browser_type, "chrome");
        assert_eq!(fp.browser_family, "chrome");
    }
}

#[test]
fn version_table_and_emulation_stay_in_sync() {
    // TLS 档 4 档，且每档的 UA / sec-ch-ua / full-version-list / TLS 名**同版本**
    assert_eq!(CHROME_VERSIONS.len(), 4);
    let mut tiers: Vec<&str> = Vec::new();
    let mut weight_sum = 0.0;
    for chrome in CHROME_VERSIONS {
        let major: u32 = chrome
            .ver
            .parse()
            .unwrap_or_else(|_| panic!("ver 必须是数字: {}", chrome.ver));
        // UA 的缩减形态 == <major>.0.0.0
        assert_eq!(
            chrome.ua_ver,
            format!("{major}.0.0.0"),
            "ua_ver 必须与 ver 同档: {}",
            chrome.impersonate
        );
        // TLS 档名 == chrome<major>
        assert_eq!(
            chrome.impersonate,
            format!("chrome{major}"),
            "TLS 档位必须等于声称的版本（{}）",
            chrome.ver
        );
        // full_ver 是 <major> 的真实构建号（不能是明显假的 .0.0）
        assert!(
            chrome.full_ver.starts_with(&format!("{major}.")),
            "full_ver 必须与 ver 同档: {}",
            chrome.full_ver
        );
        assert!(
            !chrome.full_ver.ends_with(".0.0"),
            "full_ver 不能是占位值: {}",
            chrome.full_ver
        );
        assert_eq!(
            chrome.full_ver.split('.').count(),
            4,
            "full_ver 必须是四段构建号: {}",
            chrome.full_ver
        );
        // Win11 平台版本不变
        assert_eq!(chrome.platform_version, "15.0.0");
        assert!(chrome.weight > 0.0, "权重必须为正: {}", chrome.impersonate);
        assert!(
            major <= MAX_CHROME_MAJOR.parse::<u32>().unwrap(),
            "声称的版本不能超过 wreq-util 最高档 {}: {}",
            MAX_CHROME_MAJOR,
            chrome.ver
        );
        tiers.push(chrome.impersonate);
        weight_sum += chrome.weight;
    }
    assert_eq!(weight_sum, 100.0, "TLS 档位权重合计必须是 100");
    tiers.sort_unstable();
    assert_eq!(tiers, vec!["chrome140", "chrome145", "chrome146", "chrome149"]);

    // `emulation` 必须映射到 wreq-util 上真实存在的档位，且与 UA / sec-ch-ua 同档
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(
            ["Chrome140", "Chrome145", "Chrome146", "Chrome149"].contains(&fp.emulation.as_str()),
            "emulation 只能来自 4 档: {}",
            fp.emulation
        );
        assert!(
            sentinel_rs::flow::http::parse_emulation(&fp.emulation).is_some(),
            "wreq-util 里没有 {} 这档 emulation",
            fp.emulation
        );
        assert_eq!(
            fp.emulation,
            format!("Chrome{}", fp.impersonate.trim_start_matches("chrome"))
        );
        assert!(
            fp.version_consistency().is_ok(),
            "seed={seed} 版本不自洽: {:?}",
            fp.version_consistency()
        );
    }
}

#[test]
fn forty_fingerprints_keep_ua_sec_ch_ua_and_tls_in_one_tier() {
    // 验收：40 套指纹，UA major / sec-ch-ua major / TLS 档三者完全一致，且四档都出现
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for i in 0..40 {
        let seed = format!("tier-{i}");
        let fp = DeviceFingerprint::generate(Some(&seed));

        let ua = ua_major_of(&fp.user_agent);
        let ch = sec_ch_major_of(&fp.sec_ch_ua);
        let tls = tls_major_of(&fp.emulation);

        assert_eq!(ua, ch, "[{i}] UA major 必须等于 sec-ch-ua major（{seed}）");
        assert_eq!(ch, tls, "[{i}] sec-ch-ua major 必须等于 TLS 档（{seed}）");
        assert_eq!(
            ua, fp.chrome_major,
            "[{i}] UA major 必须等于 chrome_major（{seed}）"
        );
        assert_eq!(fp.browser_version, format!("{ua}.0.0.0"), "[{i}] browser_version");
        assert_eq!(
            fp.ua_platform_version, "15.0.0",
            "[{i}] platform_version 必须保持 Win11"
        );
        assert!(
            fp.version_consistency().is_ok(),
            "[{i}] version_consistency: {:?}",
            fp.version_consistency()
        );
        // `--nocapture` 时打印 40 行验收证据（版本 / sec-ch-ua major / TLS 档）
        println!(
            "[{i:02}] ua={} sec-ch-ua={} tls={} -> {}",
            ua,
            ch,
            tls,
            fp.summary()
        );
        seen.insert(tls);
    }
    assert_eq!(
        seen.len(),
        4,
        "40 套指纹必须覆盖四个 TLS 档，实际只出现 {seen:?}"
    );
}

#[test]
fn brand_lists_are_derived_from_the_same_tier() {
    let by_impersonate = |name: &str| {
        *CHROME_VERSIONS
            .iter()
            .find(|c| c.impersonate == name)
            .expect("档位必须存在")
    };
    let c140 = by_impersonate("chrome140");
    let c145 = by_impersonate("chrome145");
    let c146 = by_impersonate("chrome146");
    let c149 = by_impersonate("chrome149");

    // 低熵形态：major 来自同一档，greasy 恒 24
    for chrome in [c140, c145, c146, c149] {
        assert_eq!(
            fingerprint::format_brand_list(&chrome, false),
            format!(
                "\"Chromium\";v=\"{v}\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"{v}\"",
                v = chrome.ver
            )
        );
    }

    // 高熵形态：同档真实构建号
    for chrome in [c140, c145, c146, c149] {
        assert_eq!(
            fingerprint::format_brand_list(&chrome, true),
            format!(
                "\"Chromium\";v=\"{v}\", \"Not?A_Brand\";v=\"24.0.0.0\", \
                 \"Google Chrome\";v=\"{v}\"",
                v = chrome.full_ver
            )
        );
    }
    // 四档的构建号必须两两不同（旧实现只有两个构建号，无法表达"同档"）
    let mut full_vers: Vec<&str> = CHROME_VERSIONS.iter().map(|c| c.full_ver).collect();
    full_vers.sort_unstable();
    full_vers.dedup();
    assert_eq!(full_vers.len(), CHROME_VERSIONS.len());

    // 生成的指纹必须和版本表逐字一致
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        let chrome = *CHROME_VERSIONS
            .iter()
            .find(|c| c.impersonate == fp.impersonate)
            .expect("impersonate 必须来自版本表");
        assert_eq!(fp.chrome_full_version, chrome.full_ver);
        assert_eq!(fp.sec_ch_ua, fingerprint::format_brand_list(&chrome, false));
        assert_eq!(
            fp.ua_full_version_list,
            fingerprint::format_brand_list(&chrome, true)
        );
    }
}

// ─────────────────────────── 3. 加权池 / 组合空间 ───────────────────────────

#[test]
fn weighted_pools_are_whitelisted_and_spread() {
    // 组合空间 = 11 屏 × 5 dpr × 9 核 × 3 内存 × 4 TLS
    assert_eq!(WIN_SCREENS.len(), 11);
    assert_eq!(DEVICE_PIXEL_RATIOS.len(), 5);
    assert_eq!(HARDWARE_CONCURRENCY.len(), 9);
    assert_eq!(DEVICE_MEMORY.len(), 3);
    assert_eq!(CHROME_VERSIONS.len(), 4);
    assert_eq!(DEVICE_COMBINATIONS, 5940);
    assert_eq!(
        WIN_SCREENS.len()
            * DEVICE_PIXEL_RATIOS.len()
            * HARDWARE_CONCURRENCY.len()
            * DEVICE_MEMORY.len()
            * CHROME_VERSIONS.len(),
        DEVICE_COMBINATIONS
    );

    // 权重全为正
    for (_, _, weight) in WIN_SCREENS {
        assert!(*weight > 0.0);
    }
    for (_, weight) in DEVICE_PIXEL_RATIOS {
        assert!(*weight > 0.0);
    }
    for (_, weight) in HARDWARE_CONCURRENCY {
        assert!(*weight > 0.0);
    }
    for (_, weight) in DEVICE_MEMORY {
        assert!(*weight > 0.0);
    }

    // 500 次抽样：取值全在白名单内，且至少出现 400 种不同设备组合
    let mut combos = std::collections::BTreeSet::new();
    for i in 0..500 {
        let fp = DeviceFingerprint::generate(Some(&format!("combo-{i}")));
        assert_eq!(fp.platform, "Win32", "Win32 恒成立（seed=combo-{i}）");
        assert!(
            fp.user_agent
                .contains(&format!("Chrome/{}", fp.browser_version)),
            "UA 与 browser_version 必须同档（seed=combo-{i}）"
        );
        assert!(
            fp.sec_ch_ua
                .contains(&format!("v=\"{}\"", fp.chrome_major)),
            "sec-ch-ua 与 chrome_major 必须同档"
        );
        assert!(
            fp.version_consistency().is_ok(),
            "seed=combo-{i} 版本不自洽: {:?}",
            fp.version_consistency()
        );
        assert!(screen_in_pool(fp.screen_width, fp.screen_height), "屏幕越界");
        assert!(dpr_in_pool(fp.device_pixel_ratio), "dpr 越界");
        assert!(cores_in_pool(fp.hardware_concurrency), "核数越界");
        assert!(memory_in_pool(fp.device_memory), "内存越界");
        assert!(fp.device_memory <= 8, "device_memory 必须 ≤ 8");
        combos.insert((
            fp.screen_width,
            fp.screen_height,
            fp.device_pixel_ratio.to_bits(),
            fp.hardware_concurrency,
            fp.device_memory,
            fp.emulation.clone(),
        ));
    }
    assert!(
        combos.len() >= 400,
        "500 次抽样只出现 {} 种设备组合（要求 ≥ 400）",
        combos.len()
    );
}

// ─────────────────────────── 4. 区域 / 语言 ───────────────────────────

#[test]
fn timezone_and_languages_come_from_the_same_country_profile() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        let profile = profile_of_timezone(&fp.timezone)
            .unwrap_or_else(|| panic!("时区 {} 不在国家画像表里（seed={seed}）", fp.timezone));
        assert!(
            profile.languages.contains(&fp.lang.as_str()),
            "{}/{} 的主语言 {} 不在语言池 {:?}",
            profile.code,
            fp.timezone,
            fp.lang,
            profile.languages
        );
        assert_eq!(
            fp.lang, profile.languages[0],
            "主语言必须固定取语言池第一位"
        );
    }
}

#[test]
fn every_country_profile_timezone_is_known_to_the_token_table() {
    // 50 个国家画像全部在表里（不是只留 11 个）
    assert_eq!(COUNTRY_PROFILES.len(), 50, "必须照抄 Python 的全部 50 个国家");
    let mut codes: Vec<&str> = COUNTRY_PROFILES.iter().map(|p| p.code).collect();
    codes.sort_unstable();
    let unique: std::collections::BTreeSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), codes.len(), "国家代码不能重复");

    // 缺一个时区 → `Profile::new` 把偏移退成默认 +540，时区名与偏移自相矛盾
    for profile in COUNTRY_PROFILES {
        for &(timezone, weight) in profile.timezones {
            assert!(weight > 0.0, "{}/{} 权重必须为正", profile.code, timezone);
            assert!(
                sentinel_rs::token::tz_table(timezone).is_some(),
                "国家画像 {} 的时区 {timezone} 不在 token::tz_table 中",
                profile.code
            );
        }
        assert!(
            !profile.languages.is_empty(),
            "{} 语言池不能为空",
            profile.code
        );
    }
    assert!(sentinel_rs::token::tz_table(DEFAULT_COUNTRY_PROFILE.timezones[0].0).is_some());
}

#[test]
fn country_forces_the_region() {
    let jp = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("JP"));
    assert_eq!(jp.timezone, "Asia/Tokyo");
    assert_eq!(jp.lang, "ja-JP");
    assert_eq!(jp.locale, "ja-JP");
    assert_eq!(jp.country_code, "JP");

    // 大小写不敏感
    let lower = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("jp"));
    assert_eq!(lower, jp, "国家代码大小写不应影响结果");

    let gb = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("GB"));
    assert_eq!(gb.timezone, "Europe/London");
    assert_eq!(gb.lang, "en-GB");

    // 未知国家 → 回退 `_DEFAULT_COUNTRY_PROFILE`（UTC + en-US），不 panic
    let unknown = DeviceFingerprint::generate_for_country(Some("country-seed"), Some("ZZ"));
    assert_eq!(unknown.timezone, "UTC");
    assert_eq!(unknown.lang, "en-US");
    assert_eq!(unknown.country_code, DEFAULT_COUNTRY_PROFILE.code);

    // 完全不给国家 → 也是默认画像（与 Python 一致）
    let none = DeviceFingerprint::generate(Some("country-seed"));
    assert_eq!(none.timezone, "UTC");
    assert_eq!(none.lang, "en-US");
}

#[test]
fn every_country_code_is_selectable() {
    for profile in COUNTRY_PROFILES {
        let fp = DeviceFingerprint::generate_for_country(Some("country-loop"), Some(profile.code));
        assert_eq!(fp.country_code, profile.code);
        assert!(
            profile.timezones.iter().any(|&(tz, _)| tz == fp.timezone),
            "{} 抽到的时区 {} 不在画像里",
            profile.code,
            fp.timezone
        );
        assert_eq!(fp.lang, profile.languages[0]);
    }
}

#[test]
fn languages_are_three_to_five_with_decreasing_q() {
    // VN 池 7 个 → 3~5 个
    let mut seen_counts = std::collections::BTreeSet::new();
    for seed in (0..200).map(|i| format!("lang-{i}")) {
        let fp = DeviceFingerprint::generate_for_country(Some(&seed), Some("VN"));
        let langs = lang_list_of(&fp.lang_full);
        assert!(
            (3..=5).contains(&langs.len()),
            "语言个数必须是 3~5: {:?}",
            langs
        );
        assert_eq!(langs[0], "vi-VN", "主语言固定语言池第一位");
        assert_eq!(langs[0], fp.lang);
        assert_eq!(fp.locale, fp.lang);
        seen_counts.insert(langs.len());

        // q 递减：0.9 / 0.8 / 0.7 / 0.6，主语言不带 q
        let parts: Vec<&str> = fp.lang_full.split(',').collect();
        assert_eq!(parts.len(), langs.len());
        assert!(!parts[0].contains(";q="), "主语言不带 q: {}", parts[0]);
        for (i, part) in parts.iter().enumerate().skip(1) {
            let expected = format!(";q=0.{}", 10 - i);
            assert!(
                part.ends_with(&expected),
                "第 {} 个语言 q 值应为 {}，实际 {}",
                i + 1,
                expected,
                part
            );
        }
        let unique: std::collections::BTreeSet<_> = langs.iter().collect();
        assert_eq!(unique.len(), langs.len(), "语言不能重复: {:?}", langs);
    }
    assert!(
        seen_counts.len() >= 2,
        "200 个 seed 应覆盖到多种语言个数: {seen_counts:?}"
    );
}

#[test]
fn weighted_timezones_are_all_reachable() {
    // US 四个时区权重 0.4/0.3/0.2/0.1；200 次抽样全都要出现
    let mut seen = std::collections::BTreeSet::new();
    for seed in (0..200).map(|i| format!("tz-{i}")) {
        let fp = DeviceFingerprint::generate_for_country(Some(&seed), Some("US"));
        assert_eq!(fp.country_code, "US");
        seen.insert(fp.timezone.clone());
    }
    for tz in [
        "America/New_York",
        "America/Los_Angeles",
        "America/Chicago",
        "America/Denver",
    ] {
        assert!(
            seen.contains(tz),
            "200 次抽样没抽到 {tz}: {seen:?}（期望 4 个全出现）"
        );
    }
}

// ─────────────────────────── 5. 屏幕 / 硬件 / id ───────────────────────────

#[test]
fn screens_and_hardware_stay_inside_the_real_device_pools() {
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(
            screen_in_pool(fp.screen_width, fp.screen_height),
            "屏幕越界: {}x{}",
            fp.screen_width,
            fp.screen_height
        );
        assert!(fp.screen_width > fp.screen_height, "桌面屏幕应是横向");
        assert!(fp.screen_height >= 700);
        assert!(
            dpr_in_pool(fp.device_pixel_ratio),
            "dpr 越界: {}",
            fp.device_pixel_ratio
        );
        assert!(cores_in_pool(fp.hardware_concurrency), "核数越界");
        assert!(
            memory_in_pool(fp.device_memory) && fp.device_memory <= 8,
            "内存越界"
        );
    }
}

#[test]
fn fingerprint_id_is_token_urlsafe_12() {
    // Python: f"fp_{secrets.token_urlsafe(12)}" → 前缀 + 16 个 base64url 字符
    let urlsafe = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    for seed in seeds() {
        let fp = DeviceFingerprint::generate(Some(&seed));
        assert!(fp.fingerprint_id.starts_with(fingerprint::FINGERPRINT_ID_PREFIX));
        let body = fp
            .fingerprint_id
            .strip_prefix(fingerprint::FINGERPRINT_ID_PREFIX)
            .expect("前缀");
        assert_eq!(
            body.chars().count(),
            16,
            "12 字节 urlsafe base64 是 16 字符: {}",
            fp.fingerprint_id
        );
        assert!(body.chars().all(urlsafe), "必须是 urlsafe base64: {body}");
        assert!(!body.contains('='), "token_urlsafe 不带 padding: {body}");
    }
}

// ─────────────────────────── 6. profile / 配置接线 ───────────────────────────

#[test]
fn profile_options_mirror_the_fingerprint() {
    for seed in ["p-1", "p-2", "p-3"] {
        let fp = DeviceFingerprint::generate(Some(seed));
        let options = fp.profile_options();

        assert_eq!(options.user_agent.as_deref(), Some(fp.user_agent.as_str()));
        assert_eq!(options.screen.as_deref(), Some(fp.screen().as_str()));
        assert_eq!(options.lang.as_deref(), Some(fp.lang.as_str()));
        assert_eq!(options.languages.as_deref(), Some(fp.lang_full.as_str()));
        assert_eq!(options.platform.as_deref(), Some(fp.platform.as_str()));
        assert_eq!(options.vendor.as_deref(), Some(fp.vendor.as_str()));
        assert_eq!(options.hardware_concurrency, Some(fp.hardware_concurrency));
        assert_eq!(options.device_memory, Some(fp.device_memory));
        assert_eq!(options.device_pixel_ratio, Some(fp.device_pixel_ratio));
        assert_eq!(options.timezone.as_deref(), Some(fp.timezone.as_str()));
        // client hints 高熵真值 / 触摸 / 移动标记也必须喂下去
        assert_eq!(
            options.ua_brands.as_ref().map(|b| b.len()),
            Some(fp.ua_brands().len())
        );
        assert_eq!(
            options.ua_platform_version.as_deref(),
            Some(fp.ua_platform_version.as_str())
        );
        assert_eq!(options.ua_arch.as_deref(), Some(fp.ua_arch.as_str()));
        assert_eq!(options.ua_bitness.as_deref(), Some(fp.ua_bitness.as_str()));
        assert_eq!(options.max_touch_points, Some(fp.max_touch_points));
        assert_eq!(options.is_mobile, Some(fp.is_mobile));

        // `Profile::new` 必须真的用上这些字段（不能再写死 0 / 空）
        let profile = sentinel_rs::token::Profile::new(
            &options,
            1_793_036_746_210.0,
            &mut sentinel_rs::token::Rng::constant(0.5),
        );
        assert_eq!(profile.ua_brands, fp.ua_brands());
        assert_eq!(profile.ua_platform_version, fp.ua_platform_version);
        assert_eq!(profile.ua_arch, fp.ua_arch);
        assert_eq!(profile.ua_bitness, fp.ua_bitness);
        assert_eq!(profile.max_touch_points, fp.max_touch_points);
        assert_eq!(profile.is_mobile, fp.is_mobile);
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
    assert_eq!(applied.accept_language, applied_fp.lang_full);

    // 默认 UA 常量必须与默认 TLS 档（http::DEFAULT_EMULATION = Chrome146）同版本，
    // 否则"覆盖检测"会漂移、且 UA 与握手版本对不上
    assert!(
        sentinel_rs::flow::DEFAULT_USER_AGENT.contains("Chrome/146.0.0.0"),
        "默认 UA 必须与默认 TLS 档 Chrome146 同版本: {}",
        sentinel_rs::flow::DEFAULT_USER_AGENT
    );

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
    assert!(profile_of_timezone(&resolved.timezone).is_some());
}

#[test]
fn auth_builder_headers_follow_the_fingerprint() {
    use sentinel_rs::flow::auth::AuthRequestBuilder;

    for seed in ["h-1", "h-2", "h-3"] {
        let fp = DeviceFingerprint::generate(Some(seed));
        let builder =
            AuthRequestBuilder::new("placeholder-ua", "en-US", "did-1").with_fingerprint(&fp);

        assert_eq!(builder.user_agent(), fp.user_agent);
        assert_eq!(builder.accept_language(), fp.lang_full);

        let hints = builder.client_hints().expect("指纹路径必须发 client hints");
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
        assert_eq!(spec.header("accept-language"), Some(fp.lang_full.as_str()));
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
        assert_eq!(profile.language, fp.lang);
        assert_eq!(profile.languages[0], fp.lang);
        assert_eq!(profile.timezone_name, fp.timezone);
        assert_eq!(profile.screen_width, fp.screen_width);
        assert_eq!(profile.screen_height, fp.screen_height);
        assert_eq!(profile.hardware_concurrency, fp.hardware_concurrency);
        assert_eq!(profile.device_memory, fp.device_memory);
        assert_eq!(profile.device_pixel_ratio, fp.device_pixel_ratio);
        assert_eq!(profile.max_touch_points, fp.max_touch_points);
        assert!(!profile.is_mobile);
        assert_eq!(profile.ua_arch, fp.ua_arch);
        assert_eq!(profile.ua_bitness, fp.ua_bitness);
        assert_eq!(profile.ua_platform_version, fp.ua_platform_version);

        // 时区偏移必须和时区名对得上（不能一边说 Europe/London 一边用 +540）
        let expected = sentinel_rs::token::tz_table(&fp.timezone)
            .expect("国家画像里的时区必须在 tz_table 中")
            .offset;
        assert_eq!(
            profile.timezone_offset, expected,
            "时区 {} 的偏移不对",
            fp.timezone
        );
        assert_ne!(profile.tz_label, fp.timezone, "时区标签不该退化成 IANA 名");
    }
}

#[test]
fn summary_contains_version_tier_platform_timezone_screen_and_id() {
    let fp = DeviceFingerprint::generate(Some("summary-seed"));
    let summary = fp.summary();
    assert!(summary.contains(&fp.browser_version), "{summary}");
    assert!(summary.contains(&format!("tls={}", fp.emulation)), "{summary}");
    assert!(summary.contains(&fp.platform), "{summary}");
    assert!(summary.contains(&fp.timezone), "{summary}");
    assert!(summary.contains(&fp.screen()), "{summary}");
    assert!(summary.contains(&fp.lang), "{summary}");
    assert!(
        summary.contains(&format!("{}c/{}g", fp.hardware_concurrency, fp.device_memory)),
        "{summary}"
    );
    assert!(
        summary.contains(&format!("fp={}", fp.fingerprint_id)),
        "{summary}"
    );
}
