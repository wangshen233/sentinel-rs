//! 从邮件正文 / 取码页 HTML 提取 6 位验证码。
//!
//! 取码页契约见 [`super::email`]：
//!   * 验证码正则语义：`(?<!\d)(\d{6})(?!\d)` —— 前后不能是数字
//!   * `<article>` 卡片收集 `class="meta"` / `class="code"` 文本
//!   * 有时间的卡片按 `after_ts` 过滤；无时间的卡片必须"新出现"
//!
//! 取码页是"最新在前"的卡片列表，所以按文档顺序取第一个满足条件的即可。

use std::collections::HashSet;

/// 从任意文本里取第一个 6 位验证码（前后不能紧邻数字）。
pub fn extract_otp(text: &str) -> Option<String> {
    extract_all(text).into_iter().next()
}

/// 取出文本里全部 6 位验证码（按出现顺序）。
pub fn extract_all(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 6 {
                out.push(text[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    out
}

/// 一张邮件卡片：`meta`（时间等元信息）+ `code`（验证码文本块）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboxCard {
    pub meta: Vec<String>,
    pub codes: Vec<String>,
}

impl InboxCard {
    /// 卡片里的第一个 6 位验证码。
    pub fn otp(&self) -> Option<String> {
        self.codes.iter().find_map(|raw| extract_otp(raw))
    }
}

enum Token<'a> {
    Start { name: &'a str, attrs: &'a str },
    End(&'a str),
    Text(&'a str),
}

fn tokenize(html: &str) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let bytes = html.as_bytes();
    while i < html.len() {
        if bytes[i] == b'<' {
            match html[i..].find('>') {
                Some(offset) => {
                    let raw = &html[i + 1..i + offset];
                    i += offset + 1;
                    if raw.starts_with('!') || raw.starts_with('?') {
                        continue; // doctype / 注释 / 处理指令
                    }
                    let (raw, closing) = match raw.strip_prefix('/') {
                        Some(rest) => (rest, true),
                        None => (raw, false),
                    };
                    let raw = raw.trim_end_matches('/');
                    let name_end = raw
                        .find(|c: char| c.is_whitespace())
                        .unwrap_or(raw.len());
                    let name = &raw[..name_end];
                    if name.is_empty() {
                        continue;
                    }
                    if closing {
                        out.push(Token::End(name));
                    } else {
                        out.push(Token::Start {
                            name,
                            attrs: &raw[name_end..],
                        });
                    }
                }
                None => {
                    out.push(Token::Text(&html[i..]));
                    break;
                }
            }
        } else {
            let end = html[i..].find('<').map(|p| i + p).unwrap_or(html.len());
            out.push(Token::Text(&html[i..end]));
            i = end;
        }
    }
    out
}

/// `class` 属性是否包含某个类名（大小写不敏感）。
fn has_class(attrs: &str, wanted: &str) -> bool {
    let lower = attrs.to_ascii_lowercase();
    let Some(pos) = lower.find("class") else {
        return false;
    };
    let rest = &attrs[pos + "class".len()..];
    let Some(eq) = rest.find('=') else {
        return false;
    };
    let rest = rest[eq + 1..].trim_start();
    let value = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next().unwrap_or("")
    } else if let Some(stripped) = rest.strip_prefix('\'') {
        stripped.split('\'').next().unwrap_or("")
    } else {
        rest.split(|c: char| c.is_whitespace() || c == '>')
            .next()
            .unwrap_or("")
    };
    value
        .split_whitespace()
        .any(|c| c.eq_ignore_ascii_case(wanted))
}

/// 解析取码页 HTML 里的邮件卡片（对齐 Python `_InboxParser` 的 article/meta/code 语义）。
pub fn parse_cards(html: &str) -> Vec<InboxCard> {
    let mut cards = Vec::new();
    let mut current: Option<InboxCard> = None;
    let mut depth = 0usize;
    let mut capture: Option<&'static str> = None;

    for token in tokenize(html) {
        match token {
            Token::Start { name, attrs } => {
                let name = name.to_ascii_lowercase();
                if name == "article" {
                    if current.is_none() {
                        current = Some(InboxCard::default());
                        depth = 1;
                    } else {
                        depth += 1;
                    }
                }
                if current.is_some() {
                    if has_class(attrs, "meta") {
                        capture = Some("meta");
                    } else if has_class(attrs, "code") {
                        capture = Some("codes");
                    }
                }
            }
            Token::Text(text) => {
                if let (Some(card), Some(slot)) = (current.as_mut(), capture) {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        match slot {
                            "meta" => card.meta.push(trimmed.to_string()),
                            _ => card.codes.push(trimmed.to_string()),
                        }
                    }
                }
            }
            Token::End(name) => {
                let name = name.to_ascii_lowercase();
                if current.is_none() {
                    continue;
                }
                if name == "div" || name == "span" {
                    capture = None;
                }
                if name == "article" {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if let Some(card) = current.take() {
                            cards.push(card);
                        }
                        capture = None;
                    }
                }
            }
        }
    }
    cards
}

/// 从卡片里挑"本次请求之后"的新验证码。
///
/// * 卡片带时间戳：`received_ts >= after_ts - 5` 即认为新鲜（对齐 Python 的 5 秒容差）。
/// * 卡片无时间戳：必须不在 `baseline`（发码前已存在的码）里。
pub fn select_fresh_otp(
    html: &str,
    after_ts: Option<i64>,
    baseline: &HashSet<String>,
) -> Option<String> {
    for card in parse_cards(html) {
        let Some(code) = card.otp() else { continue };
        match card_timestamp(&card) {
            Some(ts) => {
                let fresh = match after_ts {
                    Some(after) => ts >= after - 5,
                    None => true,
                };
                if fresh {
                    return Some(code);
                }
            }
            None => {
                if !baseline.contains(&code) {
                    return Some(code);
                }
            }
        }
    }
    None
}

/// 卡片里最早出现的可解析时间戳（unix 秒）。
pub fn card_timestamp(card: &InboxCard) -> Option<i64> {
    card.meta.iter().find_map(|raw| parse_meta_timestamp(raw))
}

/// 解析 meta 文本里的时间：`时间：2026-10-27 02:33:10` / `Time: 2026/10/27 02:33` / 纯 ISO。
///
/// 只支持注册场景实际出现的几种格式；解析失败返回 `None`（卡片按"无时间"处理）。
pub fn parse_meta_timestamp(raw: &str) -> Option<i64> {
    let lower = raw.to_ascii_lowercase();
    // 取冒号后面的部分（中文全角/半角、英文 time/date 都覆盖）
    let payload = ["时间", "時間", "time", "date"]
        .iter()
        .find_map(|key| {
            lower
                .find(key)
                .map(|pos| raw[pos + key.len()..].trim_start_matches([':', '：', ' ', '\t']))
        })
        .unwrap_or(raw);
    parse_datetime_prefix(payload)
}

fn parse_datetime_prefix(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.len() < 10 || !text.is_char_boundary(10) {
        return None;
    }
    let (date_part, rest) = (&text[..10], text[10..].trim_start());
    let mut date_iter = date_part.split(['-', '/']);
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: i64 = date_iter.next()?.parse().ok()?;
    let day: i64 = date_iter.next()?.parse().ok()?;
    if !(1970..=3000).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (mut hour, mut minute, mut second) = (0i64, 0i64, 0i64);
    let time_part = rest.trim_start_matches('T');
    if !time_part.is_empty() {
        let mut time_iter = time_part.split(':');
        if let Some(h) = time_iter.next() {
            hour = h.trim().parse().unwrap_or(0);
        }
        if let Some(m) = time_iter.next() {
            minute = m.trim().parse().unwrap_or(0);
        }
        if let Some(s) = time_iter.next() {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            second = digits.parse().unwrap_or(0);
        }
    }
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }
    Some(civil_to_unix(year, month, day, hour, minute, second))
}

/// 民用日期 → unix 秒（Howard Hinnant 的 `days_from_civil`，UTC，无外部依赖）。
fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

// ─────────────────────── JSON 取码页（固定邮箱服务常见形态）───────────────────────

/// 正文看起来像 JSON（对象 / 数组），供日志与分支判断。
pub fn looks_like_json(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// "还没有验证码"的占位标记（`{"code":"no_code",...}` 这类）。
const PENDING_MARKERS: &[&str] = &[
    "no_code",
    "nocode",
    "no-code",
    "none",
    "null",
    "pending",
    "empty",
    "waiting",
    "not_found",
    "notfound",
];

/// 该 `code` 字段值是否是"还没有码"的占位符。
fn is_pending_marker(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty()
        || PENDING_MARKERS
            .iter()
            .any(|m| trimmed.eq_ignore_ascii_case(m))
}

/// JSON 是否明确表示"还没有验证码"；是则返回原因（日志用）。
///
/// 认这三种形态：
///   * `{"success": false, ...}` / `{"ok": false, ...}`
///   * `{"code": "no_code", ...}`（占位符，不是 6 位数字）
///   * 既没有 `code` 也没有 `otp` 等字段的 JSON（纯状态页）
///
/// 返回 `None` 表示"不是待机响应"（有码 / 不是 JSON）。
pub fn json_pending_reason(body: &str) -> Option<String> {
    if !looks_like_json(body) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    pending_reason(&value)
}

fn pending_reason(value: &serde_json::Value) -> Option<String> {
    let serde_json::Value::Object(map) = value else {
        return None;
    };
    if map.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
        return Some("success=false".to_string());
    }
    if map.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
        return Some("ok=false".to_string());
    }
    match map.get("code") {
        Some(serde_json::Value::String(raw)) if is_pending_marker(raw) => {
            return Some(format!("code={raw:?}"));
        }
        Some(serde_json::Value::Null) => return Some("code=null".to_string()),
        _ => {}
    }
    // 完全没有码字段的 JSON（例如 `{"message":"暂未收到验证码","retryable":true}`）
    let mut code = None;
    let mut received_at = None;
    collect_code_fields(value, &mut code, &mut received_at, 0);
    if code.is_none() {
        let retryable = map
            .get("retryable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        return Some(if retryable {
            "无 code 字段（retryable=true）".to_string()
        } else {
            "无 code 字段".to_string()
        });
    }
    None
}

/// 从**JSON** 取码页里取验证码（`{"ok":true,"code":"746194","received_at":1794929150}`）。
///
/// 固定邮箱服务（每行 `email----code_url` 那种）常把取码链接做成 JSON API 而不是
/// HTML 卡片页，所以取码必须先认 JSON、再退回 HTML 卡片解析（行为不变）。
///
/// **待机响应不算码**（返回 `None`，调用方继续轮询，不报错）：
///   * `success=false` / `ok=false`
///   * `code` 不是 6 位数字（典型：`"no_code"`、`null`、`""`）
///   * JSON 里根本没有码字段
///
/// 嵌套形态（`data.code` / `result.code` / `data.otp`）递归查找。
///
/// 新鲜度：
///   * 有 `received_at`（unix 秒）→ `received_at >= after_ts - 5` 即认为新鲜
///     （对齐 HTML 卡片路径的 5 秒容差）；
///   * 没有时间戳 → 只要不在 `baseline` 里就算新鲜。
pub fn select_code_from_json(
    body: &str,
    after_ts: Option<i64>,
    baseline: &HashSet<String>,
) -> Option<String> {
    if !looks_like_json(body) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    // 待机响应（`success=false` / `code="no_code"`）一律当"还没有码"。
    if pending_reason(&value).is_some() {
        return None;
    }

    let mut code: Option<String> = None;
    let mut received_at: Option<i64> = None;
    collect_code_fields(&value, &mut code, &mut received_at, 0);

    let code = code?;
    if baseline.contains(&code) {
        return None;
    }
    match (received_at, after_ts) {
        (Some(ts), Some(after)) => (ts >= after - 5).then_some(code),
        _ => Some(code),
    }
}

/// 在 JSON 里递归找验证码字段与时间戳字段（深度受限，避免病态输入）。
fn collect_code_fields(
    value: &serde_json::Value,
    code: &mut Option<String>,
    received_at: &mut Option<i64>,
    depth: usize,
) {
    const CODE_KEYS: &[&str] = &[
        "code",
        "otp",
        "verification_code",
        "verificationcode",
        "verify_code",
    ];
    const TS_KEYS: &[&str] = &["received_at", "receivedat", "timestamp", "ts", "time"];

    if depth > 6 || value.is_null() {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                let key_lower = key.to_ascii_lowercase();
                if code.is_none() && CODE_KEYS.contains(&key_lower.as_str()) {
                    let raw = match item {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => String::new(),
                    };
                    if let Some(found) = extract_otp(&raw) {
                        *code = Some(found);
                    }
                }
                if received_at.is_none() && TS_KEYS.contains(&key_lower.as_str()) {
                    if let Some(ts) = item.as_i64() {
                        // 毫秒时间戳顺手归一成秒
                        *received_at = Some(if ts > 1_000_000_000_000 { ts / 1000 } else { ts });
                    }
                }
                collect_code_fields(item, code, received_at, depth + 1);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_code_fields(item, code, received_at, depth + 1);
            }
        }
        _ => {}
    }
}
