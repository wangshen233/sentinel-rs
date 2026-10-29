//! C ABI 导出：把注册核心编成 DLL，供 Python ctypes / C# / Go 等直接调用。
//!
//! 约定：
//! * 所有函数返回 `*mut c_char`（UTF-8、NUL 结尾），调用方必须用 [`srs_free`] 释放；
//! * 出错时返回以 `ERR:` 开头的字符串，不抛异常、不跨 FFI panic；
//! * 入参字符串都是 NUL 结尾的 UTF-8。

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::mint;
use crate::so;
use crate::token::{Profile, ProfileOptions, Rng};

fn to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("ERR: 结果包含 NUL 字节").unwrap().into_raw(),
    }
}

unsafe fn read_str(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("ERR: 空指针".into());
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("ERR: 非法 UTF-8: {e}"))
}

fn profile_from_json(fp_json: &str, rng: &mut Rng) -> Result<Profile, String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let trimmed = fp_json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Profile::new(&ProfileOptions::default(), now_ms, rng));
    }
    let fp: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("ERR: 指纹 JSON 非法: {e}"))?;
    Profile::from_fingerprint(&fp, now_ms, rng).map_err(|e| format!("ERR: 构造 profile 失败: {e}"))
}

fn guard<F: FnOnce() -> String>(f: F) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => to_c(s),
        Err(_) => to_c("ERR: Rust panic（已捕获）".into()),
    }
}

/// 版本号
#[no_mangle]
pub extern "C" fn srs_version() -> *mut c_char {
    to_c(env!("CARGO_PKG_VERSION").to_string())
}

/// 释放本库返回的字符串
#[no_mangle]
pub unsafe extern "C" fn srs_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// dx 程序 → `t`（turnstile token）
#[no_mangle]
pub unsafe extern "C" fn srs_mint_t(
    dx: *const c_char,
    p: *const c_char,
    fp_json: *const c_char,
) -> *mut c_char {
    let dx = match read_str(dx) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    let p = match read_str(p) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    let fp = match read_str(fp_json) {
        Ok(v) => v,
        Err(_) => "null".to_string(),
    };
    guard(move || {
        let mut rng = Rng::system();
        match profile_from_json(&fp, &mut rng) {
            Ok(profile) => match mint::mint_t(&dx, &p, &profile) {
                Ok(t) => t,
                Err(e) => format!("ERR: mint_t 失败: {e}"),
            },
            Err(e) => e,
        }
    })
}

/// collector + snapshot → `so`（session observer token）
#[no_mangle]
pub unsafe extern "C" fn srs_mint_so(
    collector_dx: *const c_char,
    snapshot_dx: *const c_char,
    p: *const c_char,
    fp_json: *const c_char,
) -> *mut c_char {
    let collector = match read_str(collector_dx) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    let snapshot = match read_str(snapshot_dx) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    let p = match read_str(p) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    let fp = match read_str(fp_json) {
        Ok(v) => v,
        Err(_) => "null".to_string(),
    };
    guard(move || {
        let mut rng = Rng::system();
        match profile_from_json(&fp, &mut rng) {
            Ok(profile) => match so::mint_so_full(&collector, &snapshot, &p, &profile, &mut rng) {
                Ok(out) => out.so,
                Err(e) => format!("ERR: mint_so 失败: {e}"),
            },
            Err(e) => e,
        }
    })
}

/// 生成 requirements token（PoW）
#[no_mangle]
pub unsafe extern "C" fn srs_requirements_token(fp_json: *const c_char) -> *mut c_char {
    let fp = match read_str(fp_json) {
        Ok(v) => v,
        Err(_) => "null".to_string(),
    };
    guard(move || {
        let mut rng = Rng::system();
        let profile = match profile_from_json(&fp, &mut rng) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let sid = uuid::Uuid::new_v4().to_string();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let mut ctx = crate::token::TokenCtx::new(now_ms, Rng::system());
        let seed = uuid::Uuid::new_v4().to_string();
        match crate::token::requirements_token(&profile, &sid, &seed, &mut ctx) {
            Ok(tok) => tok,
            Err(e) => format!("ERR: requirements_token 失败: {e}"),
        }
    })
}

/// 跑一次注册。`cfg_json` 是扁平 JSON 对象，键与 .env 同名：
/// `{"SENTINEL_PROXY":"socks5h://...","SENTINEL_COUNT":"1","SENTINEL_LIVE_REGISTER":"1",...}`
#[no_mangle]
pub unsafe extern "C" fn srs_register(cfg_json: *const c_char) -> *mut c_char {
    let raw = match read_str(cfg_json) {
        Ok(v) => v,
        Err(e) => return to_c(e),
    };
    guard(move || {
        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => return format!("ERR: 配置 JSON 非法: {e}"),
        };
        let mut map: HashMap<String, String> = HashMap::new();
        if let Some(obj) = parsed.as_object() {
            for (k, v) in obj {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => continue,
                    other => other.to_string(),
                };
                map.insert(k.clone(), val);
            }
        }
        let cfg = match crate::flow::RegisterConfig::from_lookup(|k: &str| map.get(k).cloned()) {
            Ok(c) => c,
            Err(e) => return format!("ERR: 配置解析失败: {e:#}"),
        };
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => return format!("ERR: 创建 runtime 失败: {e}"),
        };
        match rt.block_on(crate::flow::register_once(&cfg)) {
            Ok(outcome) => {
                let json = serde_json::json!({
                    "ok": true,
                    "dry_run": outcome.dry_run,
                    "email": outcome.email,
                    "password": outcome.password,
                    "access_token": outcome.access_token,
                    "totp_secret": outcome.totp_secret,
                    "account_id": outcome.account_id,
                });
                json.to_string()
            }
            Err(e) => format!("ERR: 注册失败: {e:#}"),
        }
    })
}
