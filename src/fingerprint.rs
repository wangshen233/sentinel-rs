//! 设备指纹生成器：每次注册现场抽一套**随机但自洽**的 Chrome-on-Windows 画像。
//!
//! 真相源是 Python 协议机（真机对齐版）`协议/fingerprint.py` 的
//! [`_gen_chrome`] / [`_format_brand_list`] / [`_apply_hardware`] /
//! [`generate_fingerprint`] / [`_COUNTRY_PROFILES`] / [`_WIN_SCREENS`] /
//! [`_HARDWARE_PROFILES`] / [`validate_fingerprint`]，本文件逐条照抄其取值与权重。
//!
//! 输出同时喂给三处，保证字节级一致（任何一处不同都会让整套指纹"穿帮"）：
//!   * HTTP 头 —— UA / `accept-language` / `sec-ch-ua*`（见 [`crate::flow::auth`]）
//!   * sentinel token profile —— [`crate::token::Profile`]（见 [`crate::flow::sentinel::profile_from_fp`]）
//!   * TLS/HTTP2 emulation —— `wreq_util::Emulation::Chrome146` / `Chrome145`
//!     （见 [`crate::flow::http`]）
//!
//! ## 为什么只有 Windows 一条路径
//!
//! 真机抓包里 Chrome 只出现在 Windows 上：UA 是
//! `(Windows NT 10.0; Win64; x64)`、`navigator.platform=Win32`、
//! `sec-ch-ua-platform="Windows"`。Python 侧 `validate_fingerprint()` 对
//! `browser_type == "chrome"` 直接断言 `navigator_platform == "Win32"`，所以
//! "Chrome on macOS"（MacIntel）在真机上**不存在**，生成出来就是一眼假。
//! 本模块因此**删掉了 macOS 分支**，`platform` 恒为 `Win32`、`vendor` 恒为
//! `Google Inc.`。
//!
//! ## 版本三兄弟必须分开，但必须**同属一个档位**（2026-11-18 修正）
//!
//! | 字段 | 值（示例，Chrome149 档） | 用在哪 |
//! |---|---|---|
//! | `ver` | `149` | `sec-ch-ua` 的 brand 版本（只有 major） |
//! | `ua_ver` | `149.0.0.0` | UA 里的缩减形式 `Chrome/149.0.0.0` |
//! | `full_ver` | `149.0.7778.180` | 高熵 `full-version-list` |
//!
//! 拿一个 `full_ver` 同时拼 UA 和 full-version-list 会造出自然界不存在的
//! `"Google Chrome";v="149.0.7778.180"`（UA）或 `Chrome/149.0.7778.180`。
//!
//! **硬规则：TLS 档位（`impersonate`）必须等于声称的版本。**
//! Python 协议机的规则是「TLS 档位必须等于声称的版本，比版本低更可疑」——
//! wreq-util 最高只到 `Chrome149`，所以**每个 TLS 档都配同版本的 UA / client hints /
//! full-version-list**（`chrome140/145/146/149` 权重 10/35/35/20），而不是统一把 UA
//! 抬到一个握手做不到的版本（旧版声称 152、实际握手 149，ja4 一比对就穿帮）。
//!
//! ## 自洽规则（生成器保证，单测逐条校验）
//!
//! | 维度 | 取值 |
//! |---|---|
//! | 平台 | Windows only：`Windows NT 10.0; Win64; x64` / `"Windows"` / `Win32` |
//! | UA 版本 | 与 TLS 档位同档：`Chrome/140.0.0.0` / `145.0.0.0` / `146.0.0.0` / `149.0.0.0` |
//! | TLS 档位 | `Chrome140` / `Chrome145` / `Chrome146` / `Chrome149`（== UA major == `sec-ch-ua` major） |
//! | sec-ch-ua | 同一档派生：`"Chromium";v="<ver>", "Not?A_Brand";v="24", "Google Chrome";v="<ver>"` |
//! | 高熵真值 | `ua_full_version_list`（同档真实构建号）/ `x86` / `64` / `""` / `15.0.0` |
//! | 时区 ↔ 语言 | 同一国家画像：[`COUNTRY_PROFILES`] 的一行，时区按权重抽 |
//! | 语言 | 3~5 个（池不足时按池长），带 `q=0.9/0.8/…` 递减；`locale == lang` |
//! | 屏幕 | [`WIN_SCREENS`] 11 档加权（1920x1080 权重 30） |
//! | dpr | [`DEVICE_PIXEL_RATIOS`] 5 档加权（**独立**抽，不与屏幕绑定） |
//! | viewport | 与 `screen` 完全相同 |
//! | 硬件 | `hardware_concurrency` 9 档加权（4~24）、`device_memory ∈ {2,4,8}`（spec 封顶 8） |
//! | 组合空间 | 11 × 5 × 9 × 3 × 4 = [`DEVICE_COMBINATIONS`]（5940）种设备组合 |
//! | 触摸 | `max_touch_points = 0`、`is_mobile = false`、`has_touch = false` |
//! | fingerprint_id | `fp_` + `secrets.token_urlsafe(12)` 形态（12 字节 urlsafe base64，16 字符） |
//!
//! ## 随机源
//!
//! 不引入新依赖：`seed=None` 时取 `rand` 的系统随机 + 时钟纳秒；
//! `seed=Some(s)` 时用 `sha1("sentinel-rs/fp/v1/" || s)` 派生，再跑 SplitMix64，
//! 所以**同 seed 必然得到同一套指纹**（指纹 id 也一样），方便回归测试 / 复现线上画像。
//!
//! ## 环境变量
//!
//! * `SENTINEL_FP_SEED` —— 给定则确定性生成（同一 seed 可复现）。
//! * `SENTINEL_FP_COUNTRY` —— 强制区域（`JP` / `GB` / `DE` …，大小写不敏感），
//!   未命中 [`COUNTRY_PROFILES`] 时回退到 [`DEFAULT_COUNTRY_PROFILE`]
//!   （`UTC` + `en-US,en`，与 Python `_DEFAULT_COUNTRY_PROFILE` 相同）。
//! * `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE` —— 显式覆盖，**此时不随机**
//!   （本模块的 [`generate_from_env`] 由 [`crate::flow`] 决定是否调用，见那里的说明）。

use base64::Engine as _;
use sha1::{Digest, Sha1};

use crate::token::{parse_brands, Brand, ProfileOptions};

/// 指纹 id 的固定前缀（方便日志里和其它 id 区分）。
pub const FINGERPRINT_ID_PREFIX: &str = "fp_";

/// greasy brand 的真值（真机 68/68 requestHeaders 同值）。
///
/// 名字带问号（`Not?A_Brand`，不是 `Not.A/Brand` / `Not/A)Brand`），版本是 24
/// 不是 99，且固定排在**第二位**（Chromium → greasy → Google Chrome）。
pub const GREASY_BRAND_NAME: &str = "Not?A_Brand";
pub const GREASY_BRAND_VERSION: &str = "24";

/// 高熵 client hints 真值（只有 Accept-CH 索取时才下发）。
pub const CHROME_UA_ARCH: &str = "x86";
pub const CHROME_UA_BITNESS: &str = "64";
/// 桌面 Chrome 的 model 是**空串的引号形式**：真机发的是 `sec-ch-ua-model: ""`。
///
/// 即 header 值本身是两个引号字符（不是"不发这个头"），所以这里是 `\"\"`。
pub const CHROME_UA_MODEL: &str = "\"\"";

/// Chrome 版本档位：**一个档位 = 一套自洽的版本三兄弟 + TLS 档**。
///
/// * `ver` —— `sec-ch-ua` 用的 major（`140` / `145` / `146` / `149`）
/// * `ua_ver` —— UA 用的缩减形式（`140.0.0.0` … `149.0.0.0`）
/// * `full_ver` —— 高熵 full-version-list 用的真实构建号（`149.0.7778.180`）
/// * `platform_version` —— `sec-ch-ua-platform-version`（Win11 = `15.0.0`）
/// * `impersonate` —— TLS/HTTP2 档位名（`chrome140/145/146/149`）
/// * `weight` —— 抽样权重（4 档合计 100）
///
/// 不变量：`ver` == `ua_ver` 的 major == `impersonate` 的版本号 == `full_ver` 的 major。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChromeVersion {
    pub impersonate: &'static str,
    pub ver: &'static str,
    pub ua_ver: &'static str,
    pub full_ver: &'static str,
    pub platform_version: &'static str,
    pub weight: f64,
}

/// 真机版本池：**每个 TLS 档都配同版本的 UA / client hints / full-version-list**。
///
/// 权重 10 / 35 / 35 / 20：主流真机落在 chrome145/146 区间，140 只在老机器上，
/// 149 是更新分支。wreq-util 最高只到 `Chrome149`，所以声称的版本上限就是 149 ——
/// 「TLS 档位必须等于声称的版本」这条硬规则在这里由 [`DeviceFingerprint::version_consistency`]
/// 与单测共同守住。
pub const CHROME_VERSIONS: &[ChromeVersion] = &[
    ChromeVersion {
        impersonate: "chrome140",
        ver: "140",
        ua_ver: "140.0.0.0",
        full_ver: "140.0.7339.207",
        platform_version: "15.0.0",
        weight: 10.0,
    },
    ChromeVersion {
        impersonate: "chrome145",
        ver: "145",
        ua_ver: "145.0.0.0",
        full_ver: "145.0.7632.160",
        platform_version: "15.0.0",
        weight: 35.0,
    },
    ChromeVersion {
        impersonate: "chrome146",
        ver: "146",
        ua_ver: "146.0.0.0",
        full_ver: "146.0.7680.178",
        platform_version: "15.0.0",
        weight: 35.0,
    },
    ChromeVersion {
        impersonate: "chrome149",
        ver: "149",
        ua_ver: "149.0.0.0",
        full_ver: "149.0.7778.180",
        platform_version: "15.0.0",
        weight: 20.0,
    },
];

/// 支持的最高 Chrome major（= wreq-util 最高档位 `Chrome149`）。
///
/// 声称的版本不可能超过它：超过就必然出现「UA 说 152、握手是 149」的穿帮组合。
pub const MAX_CHROME_MAJOR: &str = "149";

/// Windows 真实分辨率分布（11 档，权重 = 市场份额）。
///
/// `1920x1080` 权重 30（绝对主流），`1366x768` / `1536x864` / `2560x1440`
/// 次之，两档 4K 与 5:4 的老屏幕只占少量长尾。
pub const WIN_SCREENS: &[(i64, i64, f64)] = &[
    (1920, 1080, 30.0),
    (1366, 768, 12.0),
    (1536, 864, 10.0),
    (2560, 1440, 10.0),
    (1600, 900, 8.0),
    (1440, 900, 6.0),
    (1920, 1200, 4.0),
    (1680, 1050, 3.0),
    (3840, 2160, 3.0),
    (1280, 1024, 2.0),
    (2560, 1600, 2.0),
];

/// `navigator.hardwareConcurrency`（9 档，权重偏 8 / 12 / 16）。
///
/// 20 / 24 是长尾（工作站），但都是真实浏览器会报的值。
pub const HARDWARE_CONCURRENCY: &[(i64, f64)] = &[
    (4, 8.0),
    (6, 10.0),
    (8, 22.0),
    (10, 8.0),
    (12, 20.0),
    (14, 6.0),
    (16, 18.0),
    (20, 4.0),
    (24, 4.0),
];

/// `navigator.deviceMemory`（3 档）。spec 封顶 **8**，所以最大只到 8。
pub const DEVICE_MEMORY: &[(i64, f64)] = &[(2, 5.0), (4, 40.0), (8, 55.0)];

/// `window.devicePixelRatio`（Windows 缩放比例，5 档，**独立**抽取）。
pub const DEVICE_PIXEL_RATIOS: &[(f64, f64)] = &[
    (1.0, 30.0),
    (1.25, 25.0),
    (1.5, 25.0),
    (1.75, 10.0),
    (2.0, 10.0),
];

/// 设备组合空间：屏幕 × dpr × 核数 × 内存 × TLS 档 = 11 × 5 × 9 × 3 × 4。
pub const DEVICE_COMBINATIONS: usize = 11 * 5 * 9 * 3 * 4;

/// `navigator.platform` —— Chrome on Windows 恒为 `Win32`。
pub const NAVIGATOR_PLATFORM: &str = "Win32";
/// `navigator.vendor` —— Chrome 恒为 `Google Inc.`。
pub const NAVIGATOR_VENDOR: &str = "Google Inc.";
/// `sec-ch-ua-platform` 头（带引号）。
pub const SEC_CH_UA_PLATFORM: &str = "\"Windows\"";
/// `sec-ch-ua-mobile` 头（桌面端）。
pub const SEC_CH_UA_MOBILE: &str = "?0";

/// 国家/地区画像：加权时区 + 语言池（照抄 Python `_COUNTRY_PROFILES`）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CountryProfile {
    pub code: &'static str,
    /// `(IANA 时区名, 权重)`
    pub timezones: &'static [(&'static str, f64)],
    /// 语言池：第一个是主语言，其余为副语言候选
    pub languages: &'static [&'static str],
}

/// 未知国家的兜底画像（Python `_DEFAULT_COUNTRY_PROFILE`：`UTC` + `en-US,en`）。
pub const DEFAULT_COUNTRY_PROFILE: CountryProfile = CountryProfile {
    code: "",
    timezones: &[("UTC", 1.0)],
    languages: &["en-US", "en"],
};

/// 全量国家画像（顺序与 Python 一致，便于逐行对照）。
pub const COUNTRY_PROFILES: &[CountryProfile] = &[
    // ── 亚洲 ──
    CountryProfile {
        code: "JP",
        timezones: &[("Asia/Tokyo", 1.0)],
        languages: &["ja-JP", "ja", "en-US", "en", "zh-CN"],
    },
    CountryProfile {
        code: "CN",
        timezones: &[("Asia/Shanghai", 1.0)],
        languages: &["zh-CN", "zh", "en-US", "en"],
    },
    CountryProfile {
        code: "HK",
        timezones: &[("Asia/Hong_Kong", 1.0)],
        languages: &["zh-HK", "zh-CN", "zh", "en-US", "en"],
    },
    CountryProfile {
        code: "TW",
        timezones: &[("Asia/Taipei", 1.0)],
        languages: &["zh-TW", "zh", "en-US", "en", "ja"],
    },
    CountryProfile {
        code: "KR",
        timezones: &[("Asia/Seoul", 1.0)],
        languages: &["ko-KR", "ko", "en-US", "en", "ja"],
    },
    CountryProfile {
        code: "SG",
        timezones: &[("Asia/Singapore", 1.0)],
        languages: &["zh-CN", "zh", "en-US", "en", "ms-MY", "ms"],
    },
    CountryProfile {
        code: "MY",
        timezones: &[("Asia/Kuala_Lumpur", 1.0)],
        languages: &["ms-MY", "ms", "zh-CN", "zh", "en-US", "en"],
    },
    CountryProfile {
        code: "TH",
        timezones: &[("Asia/Bangkok", 1.0)],
        languages: &["th-TH", "th", "en-US", "en"],
    },
    CountryProfile {
        code: "VN",
        timezones: &[("Asia/Ho_Chi_Minh", 1.0)],
        // 主语言固定 vi-VN，副语言「6 选 2~4」，组合 9 → 510（防批量碰撞）
        languages: &["vi-VN", "vi", "en-US", "en", "en-GB", "ja-JP", "ko-KR"],
    },
    CountryProfile {
        code: "IN",
        timezones: &[("Asia/Kolkata", 1.0)],
        languages: &["en-IN", "en-US", "en", "hi-IN", "hi"],
    },
    CountryProfile {
        code: "ID",
        timezones: &[("Asia/Jakarta", 1.0)],
        languages: &["id-ID", "id", "en-US", "en"],
    },
    CountryProfile {
        code: "PH",
        timezones: &[("Asia/Manila", 1.0)],
        languages: &["en-US", "en", "tl-PH", "tl"],
    },
    CountryProfile {
        code: "PK",
        timezones: &[("Asia/Karachi", 1.0)],
        languages: &["en-US", "en", "ur-PK", "ur"],
    },
    CountryProfile {
        code: "BD",
        timezones: &[("Asia/Dhaka", 1.0)],
        languages: &["bn-BD", "bn", "en-US", "en"],
    },
    CountryProfile {
        code: "IL",
        timezones: &[("Asia/Jerusalem", 1.0)],
        languages: &["he-IL", "he", "en-US", "en", "ar"],
    },
    CountryProfile {
        code: "TR",
        timezones: &[("Europe/Istanbul", 1.0)],
        languages: &["tr-TR", "tr", "en-US", "en"],
    },
    CountryProfile {
        code: "SA",
        timezones: &[("Asia/Riyadh", 1.0)],
        languages: &["ar-SA", "ar", "en-US", "en"],
    },
    CountryProfile {
        code: "AE",
        timezones: &[("Asia/Dubai", 1.0)],
        languages: &["ar-AE", "ar", "en-US", "en"],
    },
    // ── 北美 ──
    CountryProfile {
        code: "US",
        timezones: &[
            ("America/New_York", 0.4),    // 东部（数据中心多）
            ("America/Los_Angeles", 0.3), // 西部
            ("America/Chicago", 0.2),     // 中部
            ("America/Denver", 0.1),      // 山地
        ],
        languages: &["en-US", "en", "es-US", "es", "zh-CN"],
    },
    CountryProfile {
        code: "CA",
        timezones: &[
            ("America/Toronto", 0.6),   // 东部（安大略）
            ("America/Vancouver", 0.3), // 西部（BC）
            ("America/Edmonton", 0.1),  // 山地（阿尔伯塔）
        ],
        languages: &["en-CA", "en-US", "en", "fr-CA", "fr"],
    },
    CountryProfile {
        code: "MX",
        timezones: &[("America/Mexico_City", 1.0)],
        languages: &["es-MX", "es", "en-US", "en"],
    },
    // ── 南美 ──
    CountryProfile {
        code: "BR",
        timezones: &[
            ("America/Sao_Paulo", 0.7),
            ("America/Manaus", 0.2),
            ("America/Fortaleza", 0.1),
        ],
        languages: &["pt-BR", "pt", "en-US", "en", "es"],
    },
    CountryProfile {
        code: "AR",
        timezones: &[("America/Argentina/Buenos_Aires", 1.0)],
        languages: &["es-AR", "es", "en-US", "en"],
    },
    CountryProfile {
        code: "CL",
        timezones: &[("America/Santiago", 1.0)],
        languages: &["es-CL", "es", "en-US", "en"],
    },
    CountryProfile {
        code: "CO",
        timezones: &[("America/Bogota", 1.0)],
        languages: &["es-CO", "es", "en-US", "en"],
    },
    // ── 欧洲 ──
    CountryProfile {
        code: "GB",
        timezones: &[("Europe/London", 1.0)],
        languages: &["en-GB", "en-US", "en", "fr", "de"],
    },
    CountryProfile {
        code: "DE",
        timezones: &[("Europe/Berlin", 1.0)],
        languages: &["de-DE", "de", "en-US", "en", "fr"],
    },
    CountryProfile {
        code: "FR",
        timezones: &[("Europe/Paris", 1.0)],
        languages: &["fr-FR", "fr", "en-US", "en", "de"],
    },
    CountryProfile {
        code: "IT",
        timezones: &[("Europe/Rome", 1.0)],
        languages: &["it-IT", "it", "en-US", "en", "fr"],
    },
    CountryProfile {
        code: "ES",
        timezones: &[("Europe/Madrid", 1.0)],
        languages: &["es-ES", "es", "en-US", "en", "fr"],
    },
    CountryProfile {
        code: "NL",
        timezones: &[("Europe/Amsterdam", 1.0)],
        languages: &["nl-NL", "nl", "en-US", "en", "de"],
    },
    CountryProfile {
        code: "BE",
        timezones: &[("Europe/Brussels", 1.0)],
        languages: &["nl-BE", "fr-BE", "nl", "fr", "en-US", "en"],
    },
    CountryProfile {
        code: "CH",
        timezones: &[("Europe/Zurich", 1.0)],
        languages: &["de-CH", "fr-CH", "de", "fr", "it", "en-US", "en"],
    },
    CountryProfile {
        code: "SE",
        timezones: &[("Europe/Stockholm", 1.0)],
        languages: &["sv-SE", "sv", "en-US", "en"],
    },
    CountryProfile {
        code: "NO",
        timezones: &[("Europe/Oslo", 1.0)],
        languages: &["nb-NO", "nb", "en-US", "en"],
    },
    CountryProfile {
        code: "DK",
        timezones: &[("Europe/Copenhagen", 1.0)],
        languages: &["da-DK", "da", "en-US", "en"],
    },
    CountryProfile {
        code: "FI",
        timezones: &[("Europe/Helsinki", 1.0)],
        languages: &["fi-FI", "fi", "sv", "en-US", "en"],
    },
    CountryProfile {
        code: "PL",
        timezones: &[("Europe/Warsaw", 1.0)],
        languages: &["pl-PL", "pl", "en-US", "en"],
    },
    CountryProfile {
        code: "RU",
        timezones: &[
            ("Europe/Moscow", 0.7),       // 莫斯科（MSK，主要数据中心）
            ("Asia/Yekaterinburg", 0.15), // 叶卡捷琳堡（+5）
            ("Asia/Novosibirsk", 0.15),   // 新西伯利亚（+7）
        ],
        languages: &["ru-RU", "ru", "en-US", "en"],
    },
    CountryProfile {
        code: "UA",
        timezones: &[("Europe/Kiev", 1.0)],
        languages: &["uk-UA", "uk", "ru", "en-US", "en"],
    },
    CountryProfile {
        code: "CZ",
        timezones: &[("Europe/Prague", 1.0)],
        languages: &["cs-CZ", "cs", "en-US", "en", "de"],
    },
    CountryProfile {
        code: "AT",
        timezones: &[("Europe/Vienna", 1.0)],
        languages: &["de-AT", "de", "en-US", "en"],
    },
    CountryProfile {
        code: "GR",
        timezones: &[("Europe/Athens", 1.0)],
        languages: &["el-GR", "el", "en-US", "en"],
    },
    CountryProfile {
        code: "PT",
        timezones: &[("Europe/Lisbon", 1.0)],
        languages: &["pt-PT", "pt", "en-US", "en", "es"],
    },
    // ── 大洋洲 ──
    CountryProfile {
        code: "AU",
        timezones: &[
            ("Australia/Sydney", 0.5),    // 悉尼（NSW，数据中心多）
            ("Australia/Melbourne", 0.3), // 墨尔本（VIC）
            ("Australia/Brisbane", 0.2),  // 布里斯班（QLD）
        ],
        languages: &["en-AU", "en-US", "en", "zh-CN", "zh"],
    },
    CountryProfile {
        code: "NZ",
        timezones: &[("Pacific/Auckland", 1.0)],
        languages: &["en-NZ", "en-US", "en"],
    },
    // ── 非洲 ──
    CountryProfile {
        code: "ZA",
        timezones: &[("Africa/Johannesburg", 1.0)],
        languages: &["en-ZA", "en-US", "en", "af"],
    },
    CountryProfile {
        code: "EG",
        timezones: &[("Africa/Cairo", 1.0)],
        languages: &["ar-EG", "ar", "en-US", "en"],
    },
    CountryProfile {
        code: "NG",
        timezones: &[("Africa/Lagos", 1.0)],
        languages: &["en-NG", "en-US", "en"],
    },
    CountryProfile {
        code: "KE",
        timezones: &[("Africa/Nairobi", 1.0)],
        languages: &["sw-KE", "sw", "en-US", "en"],
    },
];

/// 一位桌面 Chrome（Windows）用户的完整设备画像。
///
/// 所有字段都是**同一台机器**上能同时成立的值；`PartialEq` 用于"同 seed 可复现"的断言。
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFingerprint {
    // ── 身份 ──
    /// `fp_` + 12 字节 urlsafe base64（16 字符），对齐 Python `secrets.token_urlsafe(12)`
    pub fingerprint_id: String,
    /// 恒为 `chrome`（真机只有 Chrome on Windows 这一条路径）
    pub browser_type: String,
    /// 恒为 `chrome`
    pub browser_family: String,
    /// `JP` / `GB` / `""`（未指定时为空，走 [`DEFAULT_COUNTRY_PROFILE`]）
    pub country_code: String,

    // ── 版本 / TLS ──
    /// UA 里声称的版本：与 TLS 档同档，`140.0.0.0` / `145.0.0.0` / `146.0.0.0` / `149.0.0.0`
    pub browser_version: String,
    /// `sec-ch-ua` 用的 major：与 TLS 档同档（`140` / `145` / `146` / `149`）
    pub chrome_major: String,
    /// 高熵 full-version-list 用的真实构建号：`149.0.7778.180` 等（同档）
    pub chrome_full_version: String,
    /// wreq emulation 档位名：`Chrome146` / `Chrome149`（major 必须 == `chrome_major`）
    pub emulation: String,
    /// TLS 画像名（Python `impersonate`）：`chrome146` / `chrome149`
    pub impersonate: String,

    // ── HTTP 头 ──
    pub user_agent: String,
    /// `accept-language` 头（等价 `lang_full`）
    pub accept_language: String,
    /// 例如 `"Chromium";v="149", "Not?A_Brand";v="24", "Google Chrome";v="149"`
    pub sec_ch_ua: String,
    /// `?0`（桌面端恒为 0）
    pub sec_ch_ua_mobile: String,
    /// `"Windows"`（带引号）
    pub sec_ch_ua_platform: String,

    // ── 高熵 client hints 真值（默认不下发，站点 Accept-CH 索取时才有值）──
    /// `"Chromium";v="149.0.7778.180", "Not?A_Brand";v="24.0.0.0", "Google Chrome";v="149.0.7778.180"`
    pub ua_full_version_list: String,
    pub ua_arch: String,
    pub ua_bitness: String,
    /// `""`（两个引号字符，桌面 Chrome 的真值）
    pub ua_model: String,
    pub ua_platform_version: String,

    // ── 语言 ──
    /// 主语言（`ja-JP`）：`locale` 与 `lang_full` 的第一段都是它
    pub lang: String,
    /// `navigator.locale` / `navigator.language`（== [`Self::lang`]）
    pub locale: String,
    /// 完整 `accept-language`：`ja-JP,zh-CN;q=0.9,en;q=0.8`
    pub lang_full: String,

    // ── navigator / 硬件 ──
    /// `navigator.platform`：恒为 `Win32`
    pub platform: String,
    /// `navigator.vendor`：恒为 `Google Inc.`
    pub vendor: String,
    /// `navigator.hardwareConcurrency`
    pub hardware_concurrency: i64,
    /// `navigator.deviceMemory`（spec 封顶 8）
    pub device_memory: i64,
    /// `navigator.maxTouchPoints`（桌面 Chrome 恒为 0）
    pub max_touch_points: i64,
    /// `navigator.userAgentData.mobile`（桌面恒为 false）
    pub is_mobile: bool,
    /// `max_touch_points > 0`
    pub has_touch: bool,
    /// `window.devicePixelRatio`
    pub device_pixel_ratio: f64,

    // ── 屏幕 ──
    pub screen_width: i64,
    pub screen_height: i64,
    /// `window.innerWidth`（与屏幕宽度完全相同）
    pub viewport_w: i64,
    /// `window.innerHeight`（与屏幕高度完全相同）
    pub viewport_h: i64,

    // ── 时区 ──
    /// IANA 时区名（如 `Asia/Tokyo`）
    pub timezone: String,
}

/// 派生 seed 的域分隔前缀（避免同 seed 在别处被复用成同一串随机数）。
const SEED_DOMAIN: &[u8] = b"sentinel-rs/fp/v1/";

impl DeviceFingerprint {
    /// 生成一套指纹。`seed=None` 用系统随机；`Some(seed)` 同 seed 可复现。
    pub fn generate(seed: Option<&str>) -> Self {
        Self::generate_for_country(seed, None)
    }

    /// 生成一套指纹，并可用 `country`（如 `JP`）把区域画像钉死。
    ///
    /// 未命中国家表时回退到 [`DEFAULT_COUNTRY_PROFILE`]（`UTC` + `en-US,en`），
    /// 只打一条 warn，不 panic —— 注册链不能因为一个笔误的环境变量就整体失败。
    pub fn generate_for_country(seed: Option<&str>, country: Option<&str>) -> Self {
        let mut rng = match seed {
            Some(seed) => FpRng::from_seed(seed),
            None => FpRng::from_system(),
        };

        // 1) Chrome 版本档位：一档同时决定 UA / sec-ch-ua / full-version-list / TLS 档
        let chrome = *rng.pick_weighted_by(CHROME_VERSIONS, |c| c.weight);
        let sec_ch_ua = format_brand_list(&chrome, false);
        let ua_full_version_list = format_brand_list(&chrome, true);

        // 2) 平台：只有 Windows（macOS 分支已删，真机不存在 Chrome on macOS）
        let user_agent = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/{} Safari/537.36",
            chrome.ua_ver
        );

        // 3) 屏幕（11 档加权）+ dpr 独立抽（5 档加权）
        let &(screen_width, screen_height, _) = rng.pick_weighted_by(WIN_SCREENS, |s| s.2);
        let device_pixel_ratio = rng.pick_weighted_by(DEVICE_PIXEL_RATIOS, |p| p.1).0;

        // 4) 硬件（spec 封顶 8；核心数长尾到 24）
        let hardware_concurrency = rng.pick_weighted_by(HARDWARE_CONCURRENCY, |p| p.1).0;
        let device_memory = rng.pick_weighted_by(DEVICE_MEMORY, |p| p.1).0;
        let max_touch_points = 0i64;

        // 5) 国家画像 → 加权时区 + 语言池（3~5 个，q 递减）
        let profile = country_profile(country);
        let timezone = rng.pick_weighted_by(profile.timezones, |t| t.1).0;
        let (lang, lang_full) = pick_languages(&mut rng, profile.languages);

        // 6) 指纹 id（最后抽，保持字段顺序稳定 → 同 seed 必同 id）
        let fingerprint_id = format!(
            "{FINGERPRINT_ID_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rng.bytes(12))
        );

        let fp = Self {
            fingerprint_id,
            browser_type: "chrome".to_string(),
            browser_family: "chrome".to_string(),
            country_code: profile.code.to_string(),

            browser_version: chrome.ua_ver.to_string(),
            chrome_major: chrome.ver.to_string(),
            chrome_full_version: chrome.full_ver.to_string(),
            emulation: format!("Chrome{}", chrome.impersonate.trim_start_matches("chrome")),
            impersonate: chrome.impersonate.to_string(),

            user_agent,
            accept_language: lang_full.clone(),
            sec_ch_ua,
            sec_ch_ua_mobile: SEC_CH_UA_MOBILE.to_string(),
            sec_ch_ua_platform: SEC_CH_UA_PLATFORM.to_string(),

            ua_full_version_list,
            ua_arch: CHROME_UA_ARCH.to_string(),
            ua_bitness: CHROME_UA_BITNESS.to_string(),
            ua_model: CHROME_UA_MODEL.to_string(),
            ua_platform_version: chrome.platform_version.to_string(),

            lang: lang.clone(),
            locale: lang,
            lang_full,

            platform: NAVIGATOR_PLATFORM.to_string(),
            vendor: NAVIGATOR_VENDOR.to_string(),
            hardware_concurrency,
            device_memory,
            max_touch_points,
            is_mobile: false,
            has_touch: max_touch_points > 0,
            device_pixel_ratio,

            screen_width,
            screen_height,
            // 真机 viewport 与 screen 完全相同（Python validate_fingerprint 硬断言）
            viewport_w: screen_width,
            viewport_h: screen_height,

            timezone: timezone.to_string(),
        };
        // 硬规则自检：UA major == sec-ch-ua major == TLS 档版本（debug 构建里必炸，
        // release 下零成本；单测 `version_table_and_emulation_stay_in_sync` 兜同一件事）。
        debug_assert!(
            fp.version_consistency().is_ok(),
            "生成的指纹版本不自洽: {}",
            fp.summary()
        );
        fp
    }

    /// UA 里声称的 Chrome major（`Chrome/149.0.0.0` → `149`）。
    pub fn ua_major(&self) -> Option<&str> {
        let rest = self.user_agent.split("Chrome/").nth(1)?;
        let ver = rest.split(['.', ' ', ';']).next()?;
        (!ver.is_empty()).then_some(ver)
    }

    /// `sec-ch-ua` 里 Google Chrome brand 的 major（`v="149"` → `149`）。
    pub fn sec_ch_ua_major(&self) -> Option<&str> {
        const KEY: &str = "\"Google Chrome\";v=\"";
        let rest = self.sec_ch_ua.split(KEY).nth(1)?;
        let ver = rest.split('"').next()?;
        let major = ver.split('.').next()?;
        (!major.is_empty()).then_some(major)
    }

    /// TLS 档位的 major（`Chrome149` → `149`）。
    pub fn tls_major(&self) -> Option<&str> {
        let major = self.emulation.strip_prefix("Chrome")?;
        (!major.is_empty()).then_some(major)
    }

    /// 版本自洽校验：**UA major == `sec-ch-ua` major == TLS 档位版本**。
    ///
    /// 这是 Python 协议机的硬规则「TLS 档位必须等于声称的版本」；不自洽时返回
    /// 人话原因（单测 / 日志用）。
    pub fn version_consistency(&self) -> std::result::Result<(), String> {
        let ua = self
            .ua_major()
            .ok_or_else(|| format!("UA 里没有 Chrome/<major>: {}", self.user_agent))?;
        let ch = self
            .sec_ch_ua_major()
            .ok_or_else(|| format!("sec-ch-ua 里没有 Google Chrome 版本: {}", self.sec_ch_ua))?;
        let tls = self
            .tls_major()
            .ok_or_else(|| format!("emulation 不是 Chrome<major> 形态: {}", self.emulation))?;
        if ua == ch && ch == tls {
            Ok(())
        } else {
            Err(format!(
                "版本不自洽: UA={ua} / sec-ch-ua={ch} / TLS={tls}（必须三者相等）"
            ))
        }
    }

    /// 主语言（`accept-language` 的第一项，去掉 `;q=` 之后）：`ja-JP`。
    pub fn primary_language(&self) -> String {
        self.lang.clone()
    }

    /// `languages` 列表（`accept-language` 按 `;q=` 拆开）：`["ja-JP", "zh-CN", "en"]`。
    pub fn lang_list(&self) -> Vec<String> {
        split_accept_language(&self.lang_full)
    }

    /// `ua_brands`：从 `sec_ch_ua` 解析出的 `(brand, version)` 列表。
    pub fn ua_brands(&self) -> Vec<Brand> {
        parse_brands(&self.sec_ch_ua)
    }

    /// `token::ProfileOptions`（UA / 屏幕 / 语言 / 平台 / vendor / 硬件 / dpr / 时区
    /// + client hints 高熵真值与触摸/移动标记）。
    ///
    /// 这几项就是 sentinel token 里 `profile` 块的全部来源 —— 和 HTTP 头同一份数据，
    /// 不会出现"头说 Windows、token 说 MacIntel"。
    pub fn profile_options(&self) -> ProfileOptions {
        ProfileOptions {
            user_agent: Some(self.user_agent.clone()),
            screen: Some(self.screen()),
            lang: Some(self.lang.clone()),
            languages: Some(self.lang_full.clone()),
            platform: Some(self.platform.clone()),
            vendor: Some(self.vendor.clone()),
            hardware_concurrency: Some(self.hardware_concurrency),
            device_memory: Some(self.device_memory),
            device_pixel_ratio: Some(self.device_pixel_ratio),
            timezone: Some(self.timezone.clone()),
            ua_brands: Some(self.ua_brands()),
            ua_platform_version: Some(self.ua_platform_version.clone()),
            ua_arch: Some(self.ua_arch.clone()),
            ua_bitness: Some(self.ua_bitness.clone()),
            max_touch_points: Some(self.max_touch_points),
            is_mobile: Some(self.is_mobile),
        }
    }

    /// `"1920x1080"`（token profile / `launcher` 的 `screen` 格式）。
    pub fn screen(&self) -> String {
        format!("{}x{}", self.screen_width, self.screen_height)
    }

    /// `"1920x1080"` 形式的 viewport（与 `screen` 完全相同）。
    pub fn viewport(&self) -> String {
        format!("{}x{}", self.viewport_w, self.viewport_h)
    }

    /// 一行摘要（人工核对用）：
    /// `149.0.0.0(tls=Chrome149) / Win32 / Asia/Tokyo / 1920x1080/1.0 / ja-JP / 8c/8g / fp=...`
    ///
    /// 字段顺序：版本档（UA + TLS） / 平台 / 时区 / 屏幕/dpr / 语言 / 核数/内存 / fp id。
    /// 版本与 TLS 档**恒同档**（`149.0.0.0(tls=Chrome149)`），不会出现 152 配 149。
    pub fn summary(&self) -> String {
        format!(
            "{}(tls={}) / {} / {} / {}/{} / {} / {}c/{}g / fp={}",
            self.browser_version,
            self.emulation,
            self.platform,
            self.timezone,
            self.screen(),
            dpr_text(self.device_pixel_ratio),
            self.lang,
            self.hardware_concurrency,
            self.device_memory,
            self.fingerprint_id
        )
    }
}

/// 从环境变量生成一套指纹（`SENTINEL_FP_SEED` / `SENTINEL_FP_COUNTRY`）。
///
/// 是否调用由上层决定：显式 `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE`
/// 覆盖时上层不会调用它（见 [`crate::flow::RegisterConfig::resolve_fingerprint`]）。
pub fn generate_from_env() -> DeviceFingerprint {
    DeviceFingerprint::generate_for_country(
        seed_from_env().as_deref(),
        country_from_env().as_deref(),
    )
}

/// `SENTINEL_FP_SEED`（空 → `None`，即系统随机）。
pub fn seed_from_env() -> Option<String> {
    env_trimmed("SENTINEL_FP_SEED")
}

/// `SENTINEL_FP_COUNTRY`（空 → `None`）。调用方通常先试出口国家探测，再回落到它。
pub fn country_from_env() -> Option<String> {
    env_trimmed("SENTINEL_FP_COUNTRY").map(|c| c.to_ascii_uppercase())
}

fn env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 国家画像：命中 [`COUNTRY_PROFILES`] 就用它，否则 [`DEFAULT_COUNTRY_PROFILE`]。
pub fn country_profile(country: Option<&str>) -> CountryProfile {
    let Some(want) = country
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty())
    else {
        return DEFAULT_COUNTRY_PROFILE;
    };
    match COUNTRY_PROFILES.iter().find(|p| p.code == want) {
        Some(profile) => *profile,
        None => {
            tracing::warn!(
                "[fp] SENTINEL_FP_COUNTRY={want:?} 不在国家画像表（可用：{}），\
                 回退到 {} + {}",
                COUNTRY_PROFILES
                    .iter()
                    .map(|p| p.code)
                    .collect::<Vec<_>>()
                    .join("/"),
                DEFAULT_COUNTRY_PROFILE.timezones[0].0,
                DEFAULT_COUNTRY_PROFILE.languages.join(",")
            );
            DEFAULT_COUNTRY_PROFILE
        }
    }
}

/// 按真机排列拼 Chromium 的 brand 列表（Python `_format_brand_list`）。
///
/// 顺序固定为 Chromium / `<greasy>` / Google Chrome（greasy 在第二位）；
/// 高熵形态（`full = true`）用真实构建号 + greasy 的 `24.0.0.0` 形态。
pub fn format_brand_list(chrome: &ChromeVersion, full: bool) -> String {
    let (ver, greasy_ver) = if full {
        (
            chrome.full_ver.to_string(),
            format!("{GREASY_BRAND_VERSION}.0.0.0"),
        )
    } else {
        (chrome.ver.to_string(), GREASY_BRAND_VERSION.to_string())
    };
    format!(
        "\"Chromium\";v=\"{ver}\", \"{GREASY_BRAND_NAME}\";v=\"{greasy_ver}\", \
         \"Google Chrome\";v=\"{ver}\""
    )
}

/// 语言池 → `(主语言, accept-language)`。
///
/// 照抄 Python `generate_fingerprint` 的多语言逻辑：
///   * 取 3~5 个（池不足 3 个按池长），**第一个固定是池里的主语言**
///   * 其余打乱后取 `num - 1` 个
///   * `q` 值按位置递减：`q=0.9` / `0.8` / `0.7` / `0.6`（主语言不带 q）
fn pick_languages(rng: &mut FpRng, pool: &'static [&'static str]) -> (String, String) {
    let pool_len = pool.len().max(1);
    let lo = 3usize.min(pool_len);
    let hi = 5usize.min(pool_len);
    let num_langs = rng.randint(lo, hi);

    let primary = pool[0].to_string();
    let mut others: Vec<&'static str> = pool[1..].to_vec();
    rng.shuffle(&mut others);
    let take = num_langs.saturating_sub(1).min(others.len());

    let mut selected: Vec<String> = Vec::with_capacity(num_langs);
    selected.push(primary.clone());
    selected.extend(others.into_iter().take(take).map(str::to_string));

    let mut parts: Vec<String> = Vec::with_capacity(selected.len());
    for (i, lang) in selected.iter().enumerate() {
        if i == 0 {
            parts.push(lang.clone());
        } else {
            // Python: round(1.0 - i * 0.1, 1) → 0.9 / 0.8 / 0.7 / 0.6
            let q = ((1.0 - i as f64 * 0.1) * 10.0).round() / 10.0;
            parts.push(format!("{lang};q={q:.1}"));
        }
    }
    (primary, parts.join(","))
}

/// `accept-language` → 语言列表（去掉 `;q=`，保留顺序）。
pub fn split_accept_language(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|item| item.split(';').next().unwrap_or("").trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// `2.0` → `"2.0"`、`1.25` → `"1.25"`（Rust 的 `Display` 会把 2.0 打成 `2`）。
fn dpr_text(dpr: f64) -> String {
    let text = format!("{dpr}");
    if text.contains('.') {
        text
    } else {
        format!("{text}.0")
    }
}

// ─────────────────────────── 随机源 ───────────────────────────

/// SplitMix64：一个状态字就能跑，完全确定性，足够抽几十个离散值。
struct FpRng {
    state: u64,
}

impl FpRng {
    /// 系统随机：`rand` 的 thread_rng + 时钟纳秒（避免同纳秒冷启动撞车）。
    fn from_system() -> Self {
        use rand::Rng as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mixed = rand::thread_rng().gen::<u64>() ^ nanos.rotate_left(17);
        Self { state: mixed }
    }

    /// seed 派生：sha1 取前 8 字节 little-endian。用已有的 `sha1` crate，不引新依赖。
    fn from_seed(seed: &str) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(SEED_DOMAIN);
        hasher.update(seed.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Self {
            state: u64::from_le_bytes(bytes),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 均匀取 `[0, len)`。
    fn below(&mut self, len: usize) -> usize {
        debug_assert!(len > 0, "候选集不能为空");
        (self.next_u64() % len as u64) as usize
    }

    /// 按权重取一项（对齐 Python `random.choices(items, weights)`）。
    ///
    /// `weight` 把元素映射成权重；权重必须为正。
    fn pick_weighted_by<'a, T>(&mut self, items: &'a [T], weight: impl Fn(&T) -> f64) -> &'a T {
        debug_assert!(!items.is_empty(), "候选集不能为空");
        let total: f64 = items.iter().map(&weight).sum();
        debug_assert!(total > 0.0, "权重之和必须为正");
        // 取 64 位随机数的高 53 位，[0, 1)
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let mut cursor = unit * total;
        for item in items {
            cursor -= weight(item);
            if cursor < 0.0 {
                return item;
            }
        }
        &items[items.len() - 1]
    }

    /// `[lo, hi]` 闭区间整数（对齐 Python `random.randint`）。
    fn randint(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// Fisher–Yates 洗牌（对齐 Python `random.shuffle` 的语义：就地打乱）。
    fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }

    /// `n` 个随机字节（用于 `fp_` + `token_urlsafe(12)` 形态的 id）。
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let word = self.next_u64();
            for shift in 0..8 {
                if out.len() == n {
                    break;
                }
                out.push(((word >> (shift * 8)) & 0xFF) as u8);
            }
        }
        out
    }
}
