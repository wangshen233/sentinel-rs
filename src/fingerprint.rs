//! 设备指纹生成器：每次注册现场抽一套**随机但自洽**的浏览器画像。
//!
//! 输出同时喂给三处，保证字节级一致（任何一处不同都会让整套指纹"穿帮"）：
//!   * HTTP 头 —— UA / `accept-language` / `sec-ch-ua*`（见 [`crate::flow::auth`]）
//!   * sentinel token profile —— [`crate::token::Profile`]（见 [`crate::flow::sentinel::profile_from_fp`]）
//!   * TLS/HTTP2 emulation —— `wreq_util::Emulation::Chrome1xx`（见 [`crate::flow::http`]）
//!
//! ## 自洽规则（生成器保证，单测逐条校验）
//!
//! | 维度 | 取值 |
//! |---|---|
//! | 浏览器版本 | `145.0.0.0` / `146.0.0.0` / `149.0.0.0`，与 [`BROWSER_VERSIONS`] 里的 emulation 档位一一对应 |
//! | 平台 | Windows（`Windows NT 10.0; Win64; x64` / `"Windows"` / `Win32`）或 macOS（`Macintosh; Intel Mac OS X 10_15_7` / `"macOS"` / `MacIntel`） |
//! | 时区 ↔ 语言 | 只能从 [`REGIONS`] 的同一行里取（`Asia/Tokyo` 必配 `ja-JP`，等等） |
//! | 屏幕 | 平台各自的常见组合，`screen_height >= 700` |
//! | dpr | ∈ {1.0, 1.25, 1.5, 2.0}，且与所选屏幕组合匹配（4K 不会配 2.0@1366x768 这类怪组合） |
//! | 硬件 | `hardware_concurrency ∈ {4,8,12,16}`、`device_memory ∈ {4,8,16}` |
//! | fingerprint_id | `fp_` + 16 位 base62，完全本地派生（不依赖任何外部指纹服务） |
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
//!   未命中 [`REGIONS`] 时回退到全量随机。
//! * `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE` —— 显式覆盖，**此时不随机**
//!   （本模块的 [`generate_from_env`] 由 [`crate::flow`] 决定是否调用，见那里的说明）。

use sha1::{Digest, Sha1};

use crate::token::ProfileOptions;

/// 可用浏览器版本 + 对应的 wreq emulation 档位。
///
/// 版本必须与 emulation 同档：UA 说 145、TLS 却按 149 握手，这种不一致比写死更难查。
pub const BROWSER_VERSIONS: &[(&str, &str)] = &[
    ("145.0.0.0", "Chrome145"),
    ("146.0.0.0", "Chrome146"),
    ("149.0.0.0", "Chrome149"),
];

/// 可用国家/地区画像：`(country_code, timezone, primary_language)`。
///
/// 时区必须出现在 [`crate::token::tz_table`] 里，否则 token profile 的
/// `timezone_offset` 会退回默认 +540，和时区名自相矛盾。
pub const REGIONS: &[(&str, &str, &str)] = &[
    ("JP", "Asia/Tokyo", "ja-JP"),
    ("CN", "Asia/Shanghai", "zh-CN"),
    ("US", "America/New_York", "en-US"),
    ("GB", "Europe/London", "en-GB"),
    ("DE", "Europe/Berlin", "de-DE"),
    ("FR", "Europe/Paris", "fr-FR"),
    ("NL", "Europe/Amsterdam", "nl-NL"),
    ("SG", "Asia/Singapore", "en-SG"),
    ("AU", "Australia/Sydney", "en-AU"),
    ("KR", "Asia/Seoul", "ko-KR"),
    ("CA", "America/Toronto", "en-CA"),
];

/// 一位桌面 Chrome 用户的完整设备画像。
///
/// 所有字段都是**同一台机器**上能同时成立的值；`PartialEq` 用于"同 seed 可复现"的断言。
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    /// 例如 `"Chromium";v="145", "Not?A_Brand";v="24", "Google Chrome";v="145"`
    pub sec_ch_ua: String,
    /// `"?0"`（桌面端恒为 0）
    pub sec_ch_ua_mobile: String,
    /// `"\"Windows\""` / `"\"macOS\""`
    pub sec_ch_ua_platform: String,
    /// `navigator.platform`：`Win32` / `MacIntel`
    pub platform: String,
    /// `navigator.vendor`（Chrome 全平台都是 `Google Inc.`）
    pub vendor: String,
    pub hardware_concurrency: i64,
    pub device_memory: i64,
    pub screen_width: i64,
    pub screen_height: i64,
    pub device_pixel_ratio: f64,
    pub timezone: String,
    /// `navigator.languages` / `accept-language` 头：`"ja-JP,ja;q=0.9,en;q=0.8"`
    pub languages: String,
    /// `"145.0.0.0"`
    pub browser_version: String,
    /// wreq emulation 档位：`"Chrome145"` / `"Chrome146"` / `"Chrome149"`
    pub emulation: String,
    /// `"fp_"` + 16 位 base62
    pub fingerprint_id: String,
}

/// Windows 侧屏幕组合：`(width, height, 合理 dpr 集合)`。
const WINDOWS_SCREENS: &[(i64, i64, &[f64])] = &[
    (1366, 768, &[1.0, 1.25]),
    (1440, 900, &[1.0, 2.0]),
    (1536, 864, &[1.0, 1.25, 1.5]),
    (1600, 900, &[1.0, 1.25]),
    (1680, 1050, &[1.0, 1.25]),
    (1920, 1080, &[1.0, 1.25]),
    (1920, 1200, &[1.0, 2.0]),
    (2560, 1440, &[1.0, 1.25, 1.5]),
    (3840, 2160, &[1.0, 1.5]),
];

/// macOS 侧屏幕组合（MacBook 的 Retina 缩放比例基本都是 2.0）。
const MAC_SCREENS: &[(i64, i64, &[f64])] = &[
    (1440, 900, &[2.0]),
    (1512, 982, &[2.0]),
    (1680, 1050, &[2.0]),
    (1728, 1117, &[2.0]),
    (1920, 1200, &[1.0, 2.0]),
    (2560, 1440, &[1.0, 2.0]),
    (2560, 1600, &[1.0, 2.0]),
];

/// 平台倾向：`(is_mac, hardware_concurrency, device_memory)` 候选。
const WINDOWS_CPU: &[i64] = &[4, 8, 12, 16];
const MAC_CPU: &[i64] = &[8, 12, 16];
const WINDOWS_MEM: &[i64] = &[4, 8, 16];
const MAC_MEM: &[i64] = &[8, 16];

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// 指纹 id 的固定前缀（方便日志里和其它 id 区分）。
pub const FINGERPRINT_ID_PREFIX: &str = "fp_";

/// 派生 seed 的域分隔前缀（避免同 seed 在别处被复用成同一串随机数）。
const SEED_DOMAIN: &[u8] = b"sentinel-rs/fp/v1/";

impl DeviceFingerprint {
    /// 生成一套指纹。`seed=None` 用系统随机；`Some(seed)` 同 seed 可复现。
    pub fn generate(seed: Option<&str>) -> Self {
        Self::generate_for_country(seed, None)
    }

    /// 生成一套指纹，并可用 `country`（如 `JP`）把区域画像钉死。
    ///
    /// 未命中国家表时回退到全量随机（只打一条 warn，不 panic —— 注册链不能因为
    /// 一个笔误的环境变量就整体失败）。
    pub fn generate_for_country(seed: Option<&str>, country: Option<&str>) -> Self {
        let mut rng = match seed {
            Some(seed) => FpRng::from_seed(seed),
            None => FpRng::from_system(),
        };

        // 1) 浏览器版本 ↔ emulation 档位（同档位，单测保证）
        let (browser_version, emulation) = *rng.pick(BROWSER_VERSIONS);
        let major = major_version(browser_version);

        // 2) 平台（Windows / macOS 各一套 UA 与 navigator 字段）
        let is_mac = *rng.pick(&[false, true]);
        let (ua_platform, ua_arch, ch_platform, nav_platform) = if is_mac {
            (
                "Macintosh; Intel Mac OS X 10_15_7",
                "AppleWebKit/537.36 (KHTML, like Gecko)",
                "\"macOS\"",
                "MacIntel",
            )
        } else {
            (
                "Windows NT 10.0; Win64; x64",
                "AppleWebKit/537.36 (KHTML, like Gecko)",
                "\"Windows\"",
                "Win32",
            )
        };

        // 3) 时区 ↔ 语言：只从 REGIONS 的同一行取，绝不交叉组合
        let regions = regions_for(country);
        let &(_, timezone, primary_language) = rng.pick(regions.as_slice());

        // 4) 屏幕 + dpr（按平台各自的常见组合）
        let screens = if is_mac { MAC_SCREENS } else { WINDOWS_SCREENS };
        let &(screen_width, screen_height, dprs) = rng.pick(screens);
        let device_pixel_ratio = *rng.pick(dprs);

        // 5) 硬件参数
        let hardware_concurrency = *rng.pick(if is_mac { MAC_CPU } else { WINDOWS_CPU });
        let device_memory = *rng.pick(if is_mac { MAC_MEM } else { WINDOWS_MEM });

        // 6) 指纹 id（最后抽，保持字段顺序稳定 → 同 seed 必同 id）
        let fingerprint_id = format!("{FINGERPRINT_ID_PREFIX}{}", rng.base62(16));

        let languages = accept_language_for(primary_language);
        let user_agent = format!(
            "Mozilla/5.0 ({ua_platform}) {ua_arch} Chrome/{browser_version} Safari/537.36"
        );

        Self {
            user_agent,
            accept_language: languages.clone(),
            sec_ch_ua: format!(
                "\"Chromium\";v=\"{major}\", \"Not?A_Brand\";v=\"24\", \
                 \"Google Chrome\";v=\"{major}\""
            ),
            sec_ch_ua_mobile: "?0".to_string(),
            sec_ch_ua_platform: ch_platform.to_string(),
            platform: nav_platform.to_string(),
            // Chrome 在 Windows / macOS 上都报这个 vendor（只有 Safari 报 Apple）。
            vendor: "Google Inc.".to_string(),
            hardware_concurrency,
            device_memory,
            screen_width,
            screen_height,
            device_pixel_ratio,
            timezone: timezone.to_string(),
            languages,
            browser_version: browser_version.to_string(),
            emulation: emulation.to_string(),
            fingerprint_id,
        }
    }

    /// 主语言（`accept-language` 的第一项，去掉 `;q=` 之后）：`ja-JP`。
    pub fn primary_language(&self) -> String {
        self.accept_language
            .split(',')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    /// `token::ProfileOptions`（UA / 屏幕 / 语言 / 平台 / vendor / 硬件 / dpr / 时区）。
    ///
    /// 这几项就是 sentinel token 里 `profile` 块的全部来源 —— 和 HTTP 头同一份数据，
    /// 不会出现"头说 Windows、token 说 MacIntel"。
    pub fn profile_options(&self) -> ProfileOptions {
        ProfileOptions {
            user_agent: Some(self.user_agent.clone()),
            screen: Some(self.screen()),
            lang: Some(self.primary_language()),
            languages: Some(self.languages.clone()),
            platform: Some(self.platform.clone()),
            vendor: Some(self.vendor.clone()),
            hardware_concurrency: Some(self.hardware_concurrency),
            device_memory: Some(self.device_memory),
            device_pixel_ratio: Some(self.device_pixel_ratio),
            timezone: Some(self.timezone.clone()),
        }
    }

    /// `"1920x1080"`（token profile 的 `screen` 格式）。
    pub fn screen(&self) -> String {
        format!("{}x{}", self.screen_width, self.screen_height)
    }

    /// 一行摘要：`145.0.0.0 / Win32 / Asia/Tokyo / 1920x1080/1.0 / fp=...`。
    pub fn summary(&self) -> String {
        format!(
            "{} / {} / {} / {}/{} / fp={}",
            self.browser_version,
            self.platform,
            self.timezone,
            self.screen(),
            dpr_text(self.device_pixel_ratio),
            self.fingerprint_id
        )
    }
}

/// 从环境变量生成一套指纹（`SENTINEL_FP_SEED` / `SENTINEL_FP_COUNTRY`）。
///
/// 是否调用由上层决定：显式 `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE`
/// 覆盖时上层不会调用它（见 [`crate::flow::RegisterConfig::resolve_fingerprint`]）。
pub fn generate_from_env() -> DeviceFingerprint {
    let seed = env_trimmed("SENTINEL_FP_SEED");
    let country = env_trimmed("SENTINEL_FP_COUNTRY");
    DeviceFingerprint::generate_for_country(seed.as_deref(), country.as_deref())
}

fn env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 区域候选：给了 `country` 就只留该国家那一行；没给 / 没命中就用全表。
fn regions_for(country: Option<&str>) -> Vec<(&'static str, &'static str, &'static str)> {
    let all: Vec<(&'static str, &'static str, &'static str)> = REGIONS.to_vec();
    let Some(want) = country.map(|c| c.trim().to_ascii_uppercase()).filter(|c| !c.is_empty())
    else {
        return all;
    };
    let hit: Vec<_> = all
        .iter()
        .copied()
        .filter(|(code, _, _)| *code == want)
        .collect();
    if hit.is_empty() {
        tracing::warn!(
            "[fp] SENTINEL_FP_COUNTRY={want:?} 不在区域表（可用：{}），回退到随机区域",
            REGIONS
                .iter()
                .map(|(code, _, _)| *code)
                .collect::<Vec<_>>()
                .join("/")
        );
        return all;
    }
    hit
}

/// `145.0.0.0` → `145`
fn major_version(browser_version: &str) -> &str {
    browser_version.split('.').next().unwrap_or(browser_version)
}

/// `accept-language` 头的常见形态：主语言 + 基语言 + 英语兜底。
///
/// * `ja-JP` → `ja-JP,ja;q=0.9,en;q=0.8`
/// * `en-US` → `en-US,en;q=0.9`（英语系不再叠 `en`）
fn accept_language_for(primary: &str) -> String {
    let base = primary.split('-').next().unwrap_or(primary);
    if base.eq_ignore_ascii_case("en") {
        format!("{primary},{base};q=0.9")
    } else {
        format!("{primary},{base};q=0.9,en;q=0.8")
    }
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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// `len` 位 base62。
    fn base62(&mut self, len: usize) -> String {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(BASE62[self.below(BASE62.len())] as char);
        }
        out
    }
}
